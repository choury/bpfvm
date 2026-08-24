//===- BpfWideArgs.cpp - 补 BPF 后端调用约定的各种缺口 ---------------------===//
//
// 一个 .so 注册若干 pass，各挂在其需要的 pipeline EP。BpfWideArgsPass（Pipeline
// StartEP，所有 -O 触发）补调用约定缺口；其余（BpfVlaPass/BpfByvalTmpPass/
// BpfAtomicLowerPass）跑在 OptimizerLastEP，见文件末尾注册处。
//
// BpfWideArgsPass 改写的内容：
//
//   sret 剥离（stripSret）：clang 已把 struct 返回降级为 void f(ptr sret,...)，
//     只需删掉 BPF 后端不认的 sret 属性。
//
//   i128 返回值降级（lowerI128Returns）：clang 不对 i128 标量做 sret lowering，
//     ret i128 会让后端崩。改写成 void f(ptr, ...)，caller alloca+load。
//
//   聚合值参数归一化（lowerAggregateParams）：把会被后端展开成 >1 寄存器的参数
//     （聚合 / i128）统一成裸 ptr 传递。大聚合 clang 已 lower 成 ptr byval，剥 byval
//     属性即可；小聚合成值参数重建签名为 ptr。
//
//   >5 参数（rewriteFunction 等）：第 6 个起打包进 packed struct，通过第 5 个
//     寄存器位的指针传递。
//
//   变参函数（rewriteVarArgFunction + lowerVaIntrinsics）：改成定参 + 末尾 ptr
//     __va_base，lower 体内 va_start/va_arg/va_end/va_copy。
//
//   6 参 syscall（rewriteCallSiteSyscall6）：syscall 形式 call 最多 6 参，第 6 个
//     放 r0——用内联 asm 把第 6 参绑到 r0（clobber r1..r9 迫使 input 选 r0）。
//
// 用法：clang -target bpf -fpass-plugin=libBpfWideArgs.so ...
//
//===----------------------------------------------------------------------===*/

#include "include/bpf_syscall.h"   // BPF_CALL_ALLOCA（VLA 路径用）

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// BPF 后端限制是 5 个参数，所以 >5 就需要打包。
// 第 5 个位置用来放结构体指针，前 4 个仍是寄存器参数。
constexpr unsigned KEEP_REGS = 4;          // 保留为寄存器参数的个数
constexpr unsigned BPF_ARG_LIMIT = 5;      // BPF 后端的硬上限

// 通用排除条件：对所有改写路径都适用。
// 排除 llvm.* / __clang_ 等内部符号、intrinsic。
static bool isInternalOrIntrinsic(Function &F) {
    if (F.getName().starts_with("llvm."))
        return true;
    if (F.getIntrinsicID() != Intrinsic::not_intrinsic)
        return true;
    return false;
}

// callee 是 syscall 形式（inttoptr(<id>) to ptr）吗？后端把它 lower 成
// `call <imm>`（src_reg=0）。可能是常量折叠后的 ConstantExpr，或内联后尚未
// constprop 的 IntToPtr 指令（pass 跑在 PipelineStartEP 早于 instcombine）。
// BPF 用户态用 inttoptr 当函数指针只有 syscall 这一种，不会误判。
static bool isSyscallCallee(Value *Callee) {
    if (auto *CE = dyn_cast<ConstantExpr>(Callee))
        return CE->getOpcode() == Instruction::IntToPtr;
    if (auto *I = dyn_cast<Instruction>(Callee))
        return I->getOpcode() == Instruction::IntToPtr;
    return false;
}

// 判断一个函数是否是变参函数（需要 varargs 改写路径）。
// 包含：有定义的变参函数、被调用的变参声明（prototype）。
// 排除：无定义且无人调用、内部符号/intrinsic。
static bool isVarArgFunction(Function &F) {
    if (F.isDeclaration() && F.use_empty())
        return false;                      // 无定义又没人调用，不用管
    if (isInternalOrIntrinsic(F))
        return false;
    return F.isVarArg();
}

// 判断一个函数是否需要改写（>5 参数路径）：
//  - 参数个数 > 5
//  - 不是变参（变参走 isVarArgFunction 单独路径）
//  - 不是声明（要么有定义体，要么是用户声明的 prototype——但只有有 call 点才有意义）
// 排除 llvm.* / __clang_ 等内部符号。
bool needsRewrite(Function &F) {
    if (F.isDeclaration() && F.use_empty())
        return false;                      // 无定义又没人调用，不用管
    if (F.isVarArg())
        return false;                      // 变参走 isVarArgFunction 路径
    if (isInternalOrIntrinsic(F))
        return false;
    return F.arg_size() > BPF_ARG_LIMIT;
}

// 构造打包结构体类型：把第 KEEP_REGS（即第5个，索引4）之后的参数类型依次放进去。
// 注意：原本第 5 个参数（索引 4）也要进结构体，因为第 5 个寄存器位留给指针本身。
//
// 用 **packed** 结构体：字段偏移 = 各字段 allocSize 之和，无对齐填充。这样 caller 侧
// （用 i8* + 字节偏移 store 共享缓冲区）与 callee 侧（用结构体 GEP+Load）的布局自洽。
StructType *buildPackType(Function &F) {
    SmallVector<Type *, 8> elems;
    for (auto it = F.arg_begin() + KEEP_REGS; it != F.arg_end(); ++it) {
        elems.push_back(it->getType());
    }
    // 用函数名命名，便于调试 & 跨模块一致；packed 保证字段偏移 = allocSize 之和
    return StructType::create(F.getContext(), elems,
                              ("__bpf_pack_" + F.getName()).str(),
                              true /*packed*/);
}

// 构造新签名（前 KEEP_REGS 个原样 + PackTy*），克隆函数体，把对原第 5+ 参数的引用
// 替换成从结构体指针 load。返回新 Function*（旧的 dropAllReferences，由 run() 删除）。
Function *rewriteFunction(Function &F, StructType *PackTy) {
    Module &M = *F.getParent();

    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < KEEP_REGS && i < F.arg_size(); ++i)
        newArgTys.push_back(F.getFunctionType()->getParamType(i));
#if LLVM_VERSION_MAJOR >= 21
    newArgTys.push_back(PointerType::getUnqual(PackTy->getContext()));
#else
    newArgTys.push_back(PointerType::getUnqual(PackTy));
#endif

    FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, false);

    Function *NewF = Function::Create(
        newFTy, F.getLinkage(), F.getAddressSpace(),
        "__bpf_wide_tmp_" + F.getName(), &M);

    NewF->copyAttributesFrom(&F);
    NewF->setVisibility(F.getVisibility());
    NewF->setComdat(F.getComdat());
    NewF->setSection(F.getSection());
    NewF->setDSOLocal(F.isDSOLocal());

    // 声明只换签名（定义在另一 TU，那里同样改写）。调用点必须改写因后端对 >5 参的
    // 调用也拒绝，而调用点改写要求 callee 签名匹配新 ABI，故声明也必须重签。
    if (F.isDeclaration()) {
        NewF->takeName(&F);
        F.dropAllReferences();
        return NewF;
    }

    NewF->splice(NewF->end(), &F);
    NewF->takeName(&F);

    // 入口插 gep+load 重建第 5+ 参数的值。
    //    插入点：函数入口块第一个非 phi、非 alloca 指令前（保证支配所有 use）。
    BasicBlock &Entry = NewF->front();
    Instruction *InsertPt = &Entry.front();
    // 跳过前导 phi / alloca；getNextNode 可能为 null（块全是 phi/alloca 且无终止符，
    // 罕见但可能），需要判空，否则 isa<PHINode>(nullptr) 会触发断言崩溃。
    while (InsertPt && (isa<PHINode>(InsertPt) || isa<AllocaInst>(InsertPt)))
        InsertPt = InsertPt->getNextNode();
    if (!InsertPt) {
        // 兜底：直接插到入口块末尾（终止符之前）。
        InsertPt = Entry.getTerminator();
    }

    // 第 5 个新参数（索引 KEEP_REGS）= PackTy*
    Value *PackPtr = NewF->getArg(KEEP_REGS);

    std::vector<std::pair<Argument *, Value *>> replacements;
    unsigned oldIdx = 0;
    unsigned packIdx = 0;
    for (Argument &OldArg : F.args()) {
        if (oldIdx < KEEP_REGS) {
            // 前 4 个：映射到新函数对应参数
            replacements.emplace_back(&OldArg, NewF->getArg(oldIdx));
        } else {
            // 第 5+ 个：从结构体 load。在入口处插入 gep + load。
            IRBuilder<> GepB(InsertPt);
            Value *geps[] = {
                ConstantInt::get(Type::getInt32Ty(M.getContext()), 0),
                ConstantInt::get(Type::getInt32Ty(M.getContext()), packIdx)};
            Value *elemPtr = GepB.CreateGEP(PackTy, PackPtr, geps,
                                            "__wide." + OldArg.getName());
            Value *loaded = GepB.CreateLoad(OldArg.getType(), elemPtr,
                                            "__wide.ld." + OldArg.getName());
            replacements.emplace_back(&OldArg, loaded);
            ++packIdx;
        }
        ++oldIdx;
    }

    for (auto &[old, neu] : replacements)
        old->replaceAllUsesWith(neu);

    F.dropAllReferences();   // 旧 F 的 body 已 splice 走；call use 由 run() 处理
    return NewF;
}

// 调用点第 Threshold 个之后的实参 allocSize 之和（>5 参数路径 Threshold=KEEP_REGS，
// 变参路径 Threshold=NumNamed）。
static unsigned packBytes(CallBase *CB, const DataLayout &DL, unsigned Threshold) {
    unsigned bytes = 0, idx = 0;
    for (Value *arg : CB->args()) {
        if (idx >= Threshold)
            bytes += DL.getTypeAllocSize(arg->getType());
        ++idx;
    }
    return bytes;
}

// caller 入口块的共享字节缓冲区 [MaxBytes x i8]。同一 caller 的所有调用点（>5 参数
// + 变参混合）共用：每点 call 前从偏移 0 完整覆写，call 返回后即不再用，窗口互不重叠
//（BPF 同步执行，递归每帧独立栈帧）。把"每调用点独立 alloca"的栈膨胀压缩为单个。
static AllocaInst *allocSharedPackBuf(Function *Caller, unsigned MaxBytes) {
    IRBuilder<> EntryB(&Caller->getEntryBlock().front());
    Type *BufTy = ArrayType::get(Type::getInt8Ty(Caller->getContext()), MaxBytes);
    return EntryB.CreateAlloca(BufTy, nullptr, "__pack.buf");
}

// 改写调用点：第 Threshold 个之后的实参按 allocSize 累加字节偏移 store 进共享缓冲区，
// 前 Threshold 个原样传入，末尾追加缓冲区指针。callee 侧用 packed 结构体 GEP+Load
//（字段偏移 = allocSize 之和）或 va_arg（按 allocSize 推进）读回，与本处字节偏移自洽。
// 间接调用也用同一布局——只要 callee 最终指向被改写过的函数，无需知道具体是谁。
void rewriteCallSitePacked(CallBase *CB, Value *Callee, Value *SharedBuf,
                           unsigned Threshold) {
    IRBuilder<> B(CB);
    const DataLayout &DL = CB->getModule()->getDataLayout();
    Type *I8 = Type::getInt8Ty(CB->getContext());

    SmallVector<Value *, 8> newArgs;
    unsigned idx = 0;
    unsigned offset = 0;   // 共享缓冲区字节偏移（= packed 结构体字段偏移）
    for (Value *arg : CB->args()) {
        if (idx < Threshold) {
            newArgs.push_back(arg);
        } else {
            // 按 allocSize 累加字节偏移，逐字段 store（packed 布局）
            Value *elemPtr = B.CreateConstGEP1_32(I8, SharedBuf, offset, "__pack.field");
            B.CreateStore(arg, elemPtr);
            offset += DL.getTypeAllocSize(arg->getType());
        }
        ++idx;
    }
    newArgs.push_back(SharedBuf);

    // 显式构造非变参 FunctionType：opaque pointer 下间接调用的 callee 是 ptr 变量，
    // IRBuilder 无法推断签名；原变参调用点改写后也必须变成定参（后端仍拒绝变参调用）。
    // BPF 无异常/landingpad，只有 CallInst。
    auto *CI = cast<CallInst>(CB);
    SmallVector<Type *, 8> newArgTys;
    for (Value *V : newArgs)
        newArgTys.push_back(V->getType());
    FunctionType *NewFTy = FunctionType::get(CI->getFunctionType()->getReturnType(),
                                             newArgTys, false);
    CallInst *NC = B.CreateCall(NewFTy, Callee, newArgs);
    NC->setTailCallKind(CI->getTailCallKind());
    CI->replaceAllUsesWith(NC);
    CI->eraseFromParent();
}

// 改写 6 参 syscall 调用点为「前置内联 asm 写 r0 = 第6参 + 5 参 call」。syscall
// 形式 call 的第 6 个参数走 r0（r0 一般是返回值，但 syscall 是宿主拦截的瞬间指令，
// 调用前可作输入，调用后被返回覆盖）。用 side-effect 内联 asm input "r" + clobber
// r1..r9：后端只有 r0 不在 clobber 列表里且能承接 input，RA 别无选择把第 6 参落到
// r0；clobber r1..r5 让后端自动 spill/reload 原 5 实参。然后重建 5 参 call。完全
// 在 IR 层完成，无需改后端。<=5 参的 syscall 调用不进本函数（后端本就支持）。
static void rewriteCallSiteSyscall6(CallBase *CB, Value *Callee) {
    IRBuilder<> B(CB);
    LLVMContext &Ctx = CB->getContext();
    Type *I64Ty = Type::getInt64Ty(Ctx);

    // 第 6 个实参（索引 5）。BPF 寄存器是 64 位；若实参不是 i64，按 musl __scc()
    // 语义 sign-extend 到 i64。实际 musl 的 __syscall6 所有参数已经是 long。
    Value *arg6 = CB->getArgOperand(5);
    if (arg6->getType() != I64Ty)
        arg6 = B.CreateSExt(arg6, I64Ty, "__syscall.arg6");

    // 构造 InlineAsm：void(i64)；约束串 "r,~{r1},...,~{r9}"。
    // 空汇编体、side-effect=true 防止被优化器删除。
    FunctionType *AsmFTy = FunctionType::get(Type::getVoidTy(Ctx), {I64Ty}, false);
    InlineAsm *IA = InlineAsm::get(
        AsmFTy, /*AsmString=*/"", /*Constraints=*/"r,~{r1},~{r2},~{r3},~{r4},~{r5},~{r6},~{r7},~{r8},~{r9}",
        /*hasSideEffects=*/true);
    B.CreateCall(IA, {arg6}, "__syscall.setarg6");

    // 重建 5 参 call：原 callee（inttoptr id）+ 前 5 个实参。BPF 后端将编为
    // `call <imm>`（src_reg=0），即 5 参 syscall 形式；第 6 参通过 r0 传递。
    SmallVector<Value *, 8> newArgs;
    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < 5; ++i) {
        Value *a = CB->getArgOperand(i);
        newArgs.push_back(a);
        newArgTys.push_back(a->getType());
    }
    FunctionType *NewFTy = FunctionType::get(CB->getFunctionType()->getReturnType(),
                                             newArgTys, false /*非变参*/);
    auto *CI = cast<CallInst>(CB);
    CallInst *NC = B.CreateCall(NewFTy, Callee, newArgs);
    NC->setTailCallKind(CI->getTailCallKind());
    CI->replaceAllUsesWith(NC);
    CI->eraseFromParent();
}

// 一个待改写的调用点：调用谁（Callee：直接调用是 NewF，间接调用是函数指针 Value）、
// 第几个实参起打包（Threshold）。
struct PackSite {
    CallBase *CB;
    Value *Callee;     // 直接调用 = NewF；间接调用 = 原 callee（Value*）
    unsigned Threshold;
    bool IsSyscall = false;   // syscall 6 参特例走 rewriteCallSiteSyscall6
};

// 按 caller 聚合的调用点表，及每个 caller 所需的最大打包字节数。
using SiteMap = SmallDenseMap<Function *, SmallVector<PackSite, 8>>;
using BytesMap = SmallDenseMap<Function *, unsigned>;

// 收集调用某（旧）函数 OldF 的所有【直接】call site，按 caller 聚合到 byCaller，并更新各
// caller 的最大打包字节数 maxBytes。Threshold 决定第几个实参起需要打包（>5 路径用
// KEEP_REGS，变参路径用 NumNamed）。两条路径共用此逻辑。
static void collectCallSites(Function *OldF, Function *NewF, unsigned Threshold,
                             const DataLayout &DL, SiteMap &byCaller,
                             BytesMap &maxBytes) {
    for (User *U : OldF->users()) {
        auto *CB = dyn_cast<CallBase>(U);
        if (!CB || CB->getCalledFunction() != OldF)
            continue;
        Function *Caller = CB->getFunction();
        byCaller[Caller].push_back({CB, NewF, Threshold});
        unsigned b = packBytes(CB, DL, Threshold);
        if (b > maxBytes[Caller])
            maxBytes[Caller] = b;
    }
}

// 收集所有【间接】调用点（callee 是函数指针变量、getCalledFunction()==null）中，需要
// 打包的。两种情况：
//   - 定参调用点，实参 >5：Threshold = KEEP_REGS（前 4 个走寄存器，第 5 个起打包）。
//   - 变参调用点 (T0..Tn, ...)：Threshold = 具名参数个数 n（具名参数之后的变参实参打包）。
//     调用点的 FunctionType->getNumParams() 给出具名参数个数。
// 关键洞察：实参类型与个数信息全在调用点本身，改写时【不需要】知道 callee 是谁——
// 只要 callee 最终指向某个被本 pass 改写过的函数，它读 pack 的布局就与直接调用一致。
static void collectIndirectCallSites(Module &M, const DataLayout &DL,
                                     SiteMap &byCaller, BytesMap &maxBytes) {
    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *CB = dyn_cast<CallBase>(&I);
                if (!CB)
                    continue;
                if (CB->getCalledFunction() != nullptr)
                    continue;   // 直接调用，已由 collectCallSites 处理

                // 【syscall 路径】：callee 是 inttoptr(ConstantInt)，BPF 后端编为
                // `call <imm>`（src_reg=0）的 syscall 形式。最多 6 参：前 5 个走
                // r1..r5，第 6 个通过前置内联 asm 写到 r0（见 rewriteCallSiteSyscall6）。
                // 不走 packed struct 路径。
                if (isSyscallCallee(CB->getCalledOperand())) {
                    unsigned nargs = CB->arg_size();
                    if (nargs > 6) {
                        // syscall 硬上限 6 参；超出直接报编译期错误。
                        errs() << "BpfWideArgs: error: syscall call site has "
                               << nargs << " arguments (max 6)\n";
                        report_fatal_error("BPF syscall with > 6 arguments");
                    }
                    if (nargs < 6)
                        continue;   // <=5 参的 syscall 形式调用原本就合法，无需改写
                    // 恰好 6 参：走 syscall 路径
                    Function *Caller = CB->getFunction();
                    byCaller[Caller].push_back(
                        {CB, CB->getCalledOperand(), /*Threshold=*/6,
                         /*IsSyscall=*/true});
                    continue;
                }

                unsigned threshold;
                if (CB->getFunctionType()->isVarArg()) {
                    // 变参：具名参数之后的变参实参打包
                    threshold = CB->getFunctionType()->getNumParams();
                } else {
                    // 定参：只有 >5 参才需要打包
                    if (CB->arg_size() <= BPF_ARG_LIMIT)
                        continue;
                    threshold = KEEP_REGS;
                }
                // 变参调用点若变参实参为 0（只有具名参数），无需打包
                if (threshold >= CB->arg_size())
                    continue;
                Function *Caller = CB->getFunction();
                byCaller[Caller].push_back({CB, CB->getCalledOperand(), threshold});
                unsigned b = packBytes(CB, DL, threshold);
                if (b > maxBytes[Caller])
                    maxBytes[Caller] = b;
            }
        }
    }
}

// clang 已把 struct 返回降级为 void f(ptr sret,...)，函数体往指针写结果。这本身
// 是合法的 BPF 代码，但后端见到 sret 属性就报 "aggregate returns are not
// supported"。从函数签名和所有调用点同步剥掉该属性即可，语义不变。
bool stripSret(Module &M) {
    bool changed = false;

    // 收集有 sret 参数的函数，剥签名上的 sret（保留其它属性）。
    SmallVector<Function *, 16> funcs;
    for (Function &F : M) {
        if (F.isDeclaration())
            continue;
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            if (F.hasParamAttribute(i, Attribute::StructRet)) {
                funcs.push_back(&F);
                break;
            }
        }
    }
    if (funcs.empty())
        return false;

    for (Function *F : funcs) {
        for (unsigned i = 0; i < F->arg_size(); ++i) {
            if (F->hasParamAttribute(i, Attribute::StructRet)) {
                F->removeParamAttr(i, Attribute::StructRet);
                changed = true;
            }
        }
    }

    // 同步剥调用点上的 sret（callee 属性变了，调用点要同步）。
    for (Function *F : funcs) {
        for (User *U : F->users()) {
            if (auto *CB = dyn_cast<CallBase>(U)) {
                if (CB->getCalledFunction() != F)
                    continue;
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    if (CB->paramHasAttr(i, Attribute::StructRet)) {
                        CB->removeParamAttr(i, Attribute::StructRet);
                        changed = true;
                    }
                }
            }
        }
    }

    return changed;
}

// i128 及更大标量返回值会让后端 LowerReturn 崩（只有单个 64 位返回寄存器 r0）。
// clang 不对标量做 sret lowering，故 stripSret 救不了。这里主动改造成 sret 风格：
//   i128 f(args)  ->  void f(ptr %agg.result, args)
//   callee: ret i128 %v  ->  store %v, %agg.result; ret void
//   caller: x = call i128 f(args)  ->  alloca; call void f(ptr, args); load
// 必须跑在 lowerAggregateParams 之前，让它接管残留的 i128 参数。

// softfp 通道 VM helper（src_reg=2）由 BpfSoftFp 管辖，不由本 pass 改写。
// 注意：__multi3/__muloti4/__divti3 等 compiler-rt i128 runtime 虽返回 i128，但
// BpfSoftFp 只软化 `mul i128`【指令】（改写成 BPF_FP_MUL128），不拦截对这些函数
// 的【直接调用】——故它们仍需本 pass 降级 i128 返回值，否则显式调用时后端崩。
static bool isSoftFpSym(StringRef Name) {
    return Name.starts_with("__bpf_fp_");
}

// >8 字节标量整数返回值需要降级。聚合返回由 clang sret lowering + stripSret 处理。
static bool returnNeedsLowering(Type *T, const DataLayout &DL) {
    if (T->isVoidTy() || T->isPointerTy())
        return false;
    if (T->isIntegerTy() && DL.getTypeAllocSize(T) > 8)
        return true;
    return false;
}

bool lowerI128Returns(Module &M) {
    const DataLayout &DL = M.getDataLayout();
    LLVMContext &Ctx = M.getContext();

    // 收集需要降级的函数，构造 void + sret 指针的新签名（sret 插在首位）。
    struct Job { Function *OldF; Function *NewF; };
    SmallVector<Job, 16> jobs;
    for (Function &F : M) {
        if (isInternalOrIntrinsic(F))
            continue;
        if (F.isDeclaration() && F.use_empty())
            continue;
        if (!returnNeedsLowering(F.getReturnType(), DL))
            continue;
        if (isSoftFpSym(F.getName()))
            continue;
        SmallVector<Type *, 8> newArgTys;
        newArgTys.push_back(PointerType::getUnqual(Ctx));
        for (unsigned i = 0; i < F.arg_size(); ++i)
            newArgTys.push_back(F.getFunctionType()->getParamType(i));
        FunctionType *newFTy = FunctionType::get(Type::getVoidTy(Ctx), newArgTys, F.isVarArg());
        Function *NewF = Function::Create(newFTy, F.getLinkage(), F.getAddressSpace(),
                                          "__bpf_ret_tmp_" + F.getName(), &M);
        NewF->copyAttributesFrom(&F);
        // 返回 void 后原返回值属性不再适用，留着 verifier 会报错。
        NewF->removeRetAttr(Attribute::NoUndef);
        NewF->removeRetAttr(Attribute::ZExt);
        NewF->removeRetAttr(Attribute::SExt);
        NewF->removeRetAttr(Attribute::Range);
        NewF->setVisibility(F.getVisibility());
        NewF->setComdat(F.getComdat());
        NewF->setSection(F.getSection());
        NewF->setDSOLocal(F.isDSOLocal());
        jobs.push_back({&F, NewF});
    }
    if (jobs.empty())
        return false;

    // 搬函数体，改写所有 ret T %v -> store + ret void。
    for (auto &j : jobs) {
        Function *F = j.OldF;
        Function *NewF = j.NewF;
        if (F->isDeclaration()) {   // 声明只换签名，定义在另一 TU（那里同样改写）
            NewF->takeName(F);
            F->dropAllReferences();
            continue;
        }
        NewF->splice(NewF->end(), F);
        NewF->takeName(F);

        Argument *sretArg = NewF->getArg(0);
        sretArg->setName("__agg.result");
        std::vector<std::pair<Argument *, Value *>> replacements;
        unsigned idx = 1;
        for (Argument &OldArg : F->args()) {
            replacements.emplace_back(&OldArg, NewF->getArg(idx));
            ++idx;
        }
        for (auto &[old, neu] : replacements)
            old->replaceAllUsesWith(neu);

        for (BasicBlock &BB : *NewF) {
            ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator());
            if (!RI)
                continue;
            Value *rv = RI->getReturnValue();
            if (rv) {
                IRBuilder<> B(RI);
                B.CreateStore(rv, sretArg);
            }
#if LLVM_VERSION_MAJOR >= 21
            ReturnInst::Create(Ctx, nullptr, RI->getIterator());
#else
            ReturnInst::Create(Ctx, nullptr, RI);
#endif
            RI->eraseFromParent();
        }
        F->dropAllReferences();
    }

    // 改写调用点。RAUW 前先收集：RAUW 会因类型差给 callee 套 bitcast，使
    // getCalledFunction() 返回 null 而定位不到 job。
    DenseMap<CallBase *, Function *> sites;
    for (auto &j : jobs) {
        for (User *U : j.OldF->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB || CB->getCalledFunction() != j.OldF)
                continue;
            sites[CB] = j.OldF;
        }
    }
    DenseMap<Function *, Job *> jobByOld;
    for (auto &j : jobs)
        jobByOld[j.OldF] = &j;

    for (auto &[CB, OldF] : sites) {
        Job *j = jobByOld[OldF];
        Function *NewF = j->NewF;
        Function *Caller = CB->getFunction();
        Type *retTy = OldF->getReturnType();

        // alloca 必须在入口块（BPF 要求所有 alloca 集中入口块）。
        IRBuilder<> EntryB(&Caller->getEntryBlock(), Caller->getEntryBlock().getFirstInsertionPt());
        AllocaInst *tmp = EntryB.CreateAlloca(retTy, nullptr, "__agg.ret");
        tmp->setAlignment(Align(DL.getABITypeAlign(retTy)));

        // 实参数量变了（+1 sret），建新 CallInst 替换旧的。
        SmallVector<Value *, 8> newArgs;
        newArgs.push_back(tmp);
        for (Value *arg : CB->args())
            newArgs.push_back(arg);
        auto *CI = cast<CallInst>(CB);
        IRBuilder<> B(CI);
        CallInst *NC = B.CreateCall(NewF->getFunctionType(), NewF, newArgs);
        NC->setTailCallKind(CI->getTailCallKind());

        if (!CI->use_empty()) {
            IRBuilder<> LB(NC->getNextNode());
            Value *loaded = LB.CreateLoad(retTy, tmp, "__agg.ret.ld");
            CI->replaceAllUsesWith(loaded);
        }
        CI->eraseFromParent();
    }

    for (auto &j : jobs)
        j.OldF->replaceAllUsesWith(j.NewF);
    for (auto &j : jobs)
        j.OldF->eraseFromParent();

    return true;
}


// 聚合值参数归一化：把会被后端展开成 >1 寄存器的参数（聚合 / i128）统一成裸 ptr，
// 恒占 1 个寄存器。clang 对按值聚合参数分两种 IR 形态，这里都归一到裸 ptr：
//   - 大聚合：clang 已 lower 成 ptr byval(%T)，caller 已 memcpy 传指针。只需剥
//     byval 属性（后端见 byval 报 "pass by value not supported"），不改类型/函数体/
//     实参。caller 的 memcpy 不会被优化器误删（callee 收到无属性 ptr，优化器无法证
//     其不写，保守保留）。
//   - 小聚合成值参数（std::pair={i64,i64}、i128 等）：clang 直接用聚合值类型作参数
//     类型，后端按构成展开成多寄存器，多个这样的参数会撑爆 5 寄存器上限（"too many
//     arguments"）。重建签名（值类型->ptr）+ 搬函数体 + 入口 load + call site alloca/store。

// 后端 LowerFormalArguments 会展开成 >1 寄存器的类型：聚合（按构成，哪怕 8B 的
// {i32,i32} 也算 2 个）、i128 及更大标量（>8B）。排除指针、<=64 位标量、向量。
static bool needsLowering(Type *T, const DataLayout &DL) {
    if (T->isPointerTy())
        return false;
    if (T->isArrayTy() || T->isStructTy())
        return true;
    if (T->isIntegerTy() && DL.getTypeAllocSize(T) > 8)
        return true;
    return false;
}

// 把 callee 的聚合值参数（如 [2 x i64]）的 use 重写成通过指针参数访问，模拟 x86
// invisible-reference ABI：让指针参数直接代表值的存储位置（指向 caller 源对象）。
// clang 的典型模式是先 `store %arg, ptr %local` 把值拷贝到本地再 move/copy；若简单
// load 出值替换 %arg，move 作用于 load 副本，无法置空 caller 源对象 -> 引用计数错乱
//（见 eliminateByvalScalarTemporaries 的 #207686 注释）。
//
// 对 `store %arg, ptr %dst`：消除该 store，把 %dst 的所有 use 重定向到 %newarg
//（%dst 成了指针参数的别名），函数体里的 move/copy/load 直接作用于 caller 源对象。
// 其它 use：插 load 替换。
static void rewriteValueParamUsesToPointer(Function &F, Instruction *InsertPt,
                                           Argument *OldArg, Value *NewArg) {
    Type *valTy = OldArg->getType();

    SmallVector<Use *, 8> uses;
    for (Use &U : OldArg->uses())
        uses.push_back(&U);

    // 兜底 load（懒创建）：所有「直接值 use」共享，避免多次读且保证 InsertPt 支配。
    Value *fallbackLoad = nullptr;
    auto getFallbackLoad = [&]() -> Value * {
        if (!fallbackLoad) {
            IRBuilder<> B(InsertPt);
            fallbackLoad = B.CreateLoad(valTy, NewArg, "__agg.ld." + OldArg->getName());
        }
        return fallbackLoad;
    };

    for (Use *U : uses) {
        User *UR = U->getUser();
        auto *SI = dyn_cast<StoreInst>(UR);
        if (SI && SI->getValueOperand() == OldArg) {
            Value *dst = SI->getPointerOperand();
            // clang 对 `return __iter`（返回 by-value 聚合参数）生成 store %arg 到
            // gep(%tmp,0,0)，但后续 move 从 %tmp（alloca base）读。简单 RAUW gep 不
            // 影响 %tmp，move 从未初始化的 %tmp 读出垃圾（directory_iterator::begin/end
            // 这类 free function return by-value 聚合触发）。当 gep 字节 offset 0 且取
            // 整个 alloca（大小相等），改 RAUW alloca base。
            if (auto *GEP = dyn_cast<GetElementPtrInst>(dst)) {
                Value *base = GEP->getPointerOperand()->stripPointerCasts();
                if (auto *AI = dyn_cast<AllocaInst>(base)) {
                    const DataLayout &DL = F.getParent()->getDataLayout();
                    APInt off(DL.getIndexSizeInBits(GEP->getPointerAddressSpace()), 0);
                    if (GEP->accumulateConstantOffset(DL, off) && off.isZero() &&
                        DL.getTypeAllocSize(AI->getAllocatedType()) ==
                            DL.getTypeAllocSize(GEP->getResultElementType())) {
                        dst = AI;
                    }
                }
            }
            dst->replaceAllUsesWith(NewArg);
            SI->eraseFromParent();
            continue;
        }
        U->set(getFallbackLoad());
    }
}

// 收集函数里"需要降级的值类型聚合参数"的下标（路径 B：非 byval、非 ptr 的聚合
// 值类型）。已是 byval 的（路径 A，大聚合）不在此收集——它们只剥属性、不重建签名。
static SmallVector<unsigned, 4> collectAggregateValueParams(Function &F, const DataLayout &DL) {
    SmallVector<unsigned, 4> idxs;
    for (unsigned i = 0; i < F.arg_size(); ++i) {
        if (F.hasParamAttribute(i, Attribute::ByVal))
            continue;  // 路径 A（已是 byval ptr），走剥属性分支
        Type *ty = F.getFunctionType()->getParamType(i);
        if (needsLowering(ty, DL))
            idxs.push_back(i);
    }
    return idxs;
}

bool lowerAggregateParams(Module &M) {
    bool changed = false;
    const DataLayout &DL = M.getDataLayout();

    // 剥 byval 属性（大聚合）：参数已是 ptr，caller 已 memcpy 传指针。遍历全部 CallBase
    // 覆盖直接/间接/外部声明 callee。须先于重建签名跑：新建函数 copyAttributesFrom
    // 会带过来 byval，统一在这里清掉。
    for (Function &F : M) {
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            if (F.hasParamAttribute(i, Attribute::ByVal)) {
                F.removeParamAttr(i, Attribute::ByVal);
                changed = true;
            }
        }
    }
    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *CB = dyn_cast<CallBase>(&I);
                if (!CB)
                    continue;
                for (unsigned i = 0; i < CB->arg_size(); ++i) {
                    if (CB->paramHasAttr(i, Attribute::ByVal)) {
                        CB->removeParamAttr(i, Attribute::ByVal);
                        changed = true;
                    }
                }
            }
        }
    }

    // 重建签名（小聚合成值参数 -> 裸 ptr）。Function 不能就地改类型，先收集再统一处理。
    struct Job { Function *OldF; Function *NewF; SmallVector<unsigned, 4> agIdxs; };
    SmallVector<Job, 16> jobs;
    for (Function &F : M) {
        if (isInternalOrIntrinsic(F))
            continue;
        SmallVector<unsigned, 4> idxs = collectAggregateValueParams(F, DL);
        if (idxs.empty())
            continue;
        SmallVector<Type *, 8> newArgTys;
        for (unsigned i = 0; i < F.arg_size(); ++i) {
            Type *pTy = F.getFunctionType()->getParamType(i);
            newArgTys.push_back(needsLowering(pTy, DL)
                                    ? PointerType::getUnqual(F.getContext())
                                    : pTy);
        }
        FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, F.isVarArg());
        Function *NewF = Function::Create(newFTy, F.getLinkage(), F.getAddressSpace(),
                                           "__bpf_agg_tmp_" + F.getName(), &M);
        NewF->copyAttributesFrom(&F);
        NewF->setVisibility(F.getVisibility());
        NewF->setComdat(F.getComdat());
        NewF->setSection(F.getSection());
        NewF->setDSOLocal(F.isDSOLocal());
        jobs.push_back({&F, NewF, idxs});
        changed = true;
    }
    if (jobs.empty())
        return changed;

    // 搬函数体（有定义时），入口改写聚合值参数的 use。
    for (auto &j : jobs) {
        Function *F = j.OldF;
        Function *NewF = j.NewF;
        if (F->isDeclaration()) {   // 声明只换签名，定义在另一 TU
            NewF->takeName(F);
            F->dropAllReferences();
            continue;
        }
        NewF->splice(NewF->end(), F);
        NewF->takeName(F);

        BasicBlock &Entry = NewF->front();
        Instruction *InsertPt = &Entry.front();
        while (InsertPt && (isa<PHINode>(InsertPt) || isa<AllocaInst>(InsertPt)))
            InsertPt = InsertPt->getNextNode();
        if (!InsertPt)
            InsertPt = Entry.getTerminator();

        std::vector<std::pair<Argument *, Value *>> replacements;
        SmallSet<unsigned, 8> aggSet;
        aggSet.insert(j.agIdxs.begin(), j.agIdxs.end());
        unsigned idx = 0;
        for (Argument &OldArg : F->args()) {
            Argument *NewArg = NewF->getArg(idx);
            if (aggSet.count(idx)) {
                rewriteValueParamUsesToPointer(*NewF, InsertPt, &OldArg, NewArg);
            } else {
                replacements.emplace_back(&OldArg, NewArg);
            }
            ++idx;
        }
        for (auto &[old, neu] : replacements)
            old->replaceAllUsesWith(neu);
        F->dropAllReferences();
    }

    // 改写调用点。RAUW 前先收集：RAUW 会因类型差套 bitcast，使 getCalledFunction() 返回 null。
    DenseMap<CallBase *, Function *> sites;
    for (auto &j : jobs) {
        for (User *U : j.OldF->users()) {
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB || CB->getCalledFunction() != j.OldF)
                continue;
            sites[CB] = j.OldF;
        }
    }
    DenseMap<Function *, Job *> jobByOld;
    for (auto &j : jobs)
        jobByOld[j.OldF] = &j;

    // 聚合实参传法：
    //   - `load T, ptr %src`（clang 对非平凡 by-value 聚合的典型模式）：传 %src 指针，
    //     让 callee 与 caller 共享存储，callee 内 move 构造作用于 %src 置空源，caller
    //     后续析构 %src 是 no-op，引用计数正确（模拟 x86 invisible-ref）。
    //   - 其它（平凡聚合直接构造的值）：入口 alloca + call 前 store，传指针。
    // alloca 必须在入口块（BPF 要求 alloca 集中入口块）；store 留在 call 前（每次覆写）。
    for (auto &[CB, OldF] : sites) {
        Job *j = jobByOld[OldF];
        Function *NewF = j->NewF;
        Function *Caller = CB->getFunction();
        CB->setCalledFunction(NewF->getFunctionType(), NewF);
        for (unsigned i : j->agIdxs) {
            Value *arg = CB->getArgOperand(i);
            if (auto *LI = dyn_cast<LoadInst>(arg)) {
                CB->setArgOperand(i, LI->getPointerOperand());
                continue;
            }
            Type *aggTy = arg->getType();
            IRBuilder<> EntryB(&Caller->getEntryBlock(), Caller->getEntryBlock().getFirstInsertionPt());
            AllocaInst *tmp = EntryB.CreateAlloca(aggTy, nullptr, "__agg.arg");
            tmp->setAlignment(Align(DL.getABITypeAlign(aggTy)));
            IRBuilder<> B(CB);
            B.CreateStore(arg, tmp);
            CB->setArgOperand(i, tmp);
        }
    }

    // RAUW 残余 use（取地址等非 call use）-> NewF，删旧函数。
    for (auto &j : jobs)
        j.OldF->replaceAllUsesWith(j.NewF);
    for (auto &j : jobs)
        j.OldF->eraseFromParent();

    return changed;
}

// ===========================================================================
// by-value 非平凡析构参数（unique_ptr 8B / shared_ptr 16B 等）的 double-free 修复
//（上游 LLVM #207686）。
//
// BPF 后端把 <=16B 的非平凡析构 by-value 参数直接降级成 i64/[2 x i64] 按值传递，而不
// 走 Itanium C++ ABI 的 invisible-reference。lowerAggregateParams 把 callee 签名改
// 成 ptr 后，caller 侧的 IR 模式是：
//   %tmp = alloca T                          ; 备份临时
//   call T::T(ptr %tmp, ptr %src)            ; move-construct
//   %v  = load T, ptr %tmp                   ; 取出值
//   store %v, ptr __agg_arg                  ; 转存给 callee 的 alloca
//   call @callee(ptr __agg_arg)              ; callee move 出去后置空它自己的 ptr
//   call ~T(ptr %tmp)                        ; * 析构 %tmp——值仍是原指针->double-free
// %tmp 是多余的"中转"备份：内容已交给 callee，析构它就再次释放已被 move 走的资源。
//
// 修复：在 dtor 前插 store zeroinitializer, %tmp，清零让析构 noop。所有 load 都在
// dtor 前（备份临时只在调用前被读），清零不破坏正确性。
//
// 识别 %tmp 是"备份临时"而非普通局部对象（两条路径任一满足）：
//   - 存在 move-construct（mangling 含 C1/C2 + OS_<num>_）：从另一同类型对象 move
//     出来的备份。加 benign-use 守卫（isBenignTmpUse）排除有 move-ctor 但非备份的。
//   - size <= 8 + hasLoad + dtor：兜底 -O1 已把 move-construct inline 成 store、无 call
//     形式可识别的场景（unique_ptr 8B；16B shared_ptr 备份临时在 -O1 后被整体消除）。

// 判断 call 是否是对 %tmp 的 move-construct：
//   - mangling 以 _Z 开头，含 "C1"/"C2"（构造函数），且含 "OS" + 数字 + "_"（rvalue ref 参数）
//   - 至少 2 个参数，参数 0 是 %tmp，参数 1 是 ptr 类型
static bool isMoveConstructOf(CallInst *CI, AllocaInst *Tmp) {
    Function *Callee = CI->getCalledFunction();
    if (!Callee)
        return false;
    if (CI->arg_size() < 2)
        return false;
    if (CI->getArgOperand(0) != Tmp)
        return false;
    if (!CI->getArgOperand(1)->getType()->isPointerTy())
        return false;
    StringRef cn = Callee->getName();
    if (!cn.starts_with("_Z"))
        return false;
    if (!cn.contains("C1") && !cn.contains("C2"))
        return false;
    // rvalue ref 参数的 mangling：OS + <num> + _（如 OS2_、OS4_）
    if (!cn.contains("OS"))
        return false;
    return true;
}

// 判断 use 是否"无害"——只读出值（load）、单纯写入（store）、地址 bitcast、或
// lifetime intrinsic / 析构 / move-construct 本身。出现 GEP / atomic / 传入作为
// 非 ctor 的参数（sret/普通参数）等则视为普通局部，跳过避免误伤。
static bool isBenignTmpUse(Value *Tmp, User *U) {
    if (isa<LoadInst>(U) || isa<StoreInst>(U) || isa<BitCastInst>(U))
        return true;
    if (auto *II = dyn_cast<IntrinsicInst>(U)) {
        // llvm.lifetime.start/end 是 ptr nocapture use
        if (II->getIntrinsicID() == Intrinsic::lifetime_start ||
            II->getIntrinsicID() == Intrinsic::lifetime_end)
            return true;
        return false;
    }
    if (auto *CI = dyn_cast<CallInst>(U)) {
        // 允许析构本身 / move-construct / reset(nullptr)。它们都在上面专项判定里。
        Function *Callee = CI->getCalledFunction();
        if (!Callee)
            return false;
        StringRef cn = Callee->getName();
        if (!cn.starts_with("_Z"))
            return false;
        if (cn.contains("D0") || cn.contains("D1") || cn.contains("D2"))
            return true;          // 析构
        if (cn.contains("C1") || cn.contains("C2"))
            return true;          // 构造（含 move-construct）
        if (cn.contains("5reset"))
            return true;          // unique_ptr::reset(nullptr) inline 残留
        return false;
    }
    return false;
}

bool eliminateByvalScalarTemporaries(Module &M) {
    bool changed = false;

    for (Function &F : M) {
        for (BasicBlock &BB : F) {
            SmallVector<std::pair<AllocaInst *, CallInst *>, 8> toErase;

            for (Instruction &I : BB) {
                auto *dtor = dyn_cast<CallInst>(&I);
                if (!dtor || !dtor->getCalledFunction())
                    continue;
                // dtor 返回 void（析构/reset 语义），arg0 是待析构 alloca
                if (!dtor->getCalledFunction()->getReturnType()->isVoidTy())
                    continue;
                if (dtor->arg_size() < 1)
                    continue;
                auto *tmp = dyn_cast<AllocaInst>(dtor->getArgOperand(0));
                if (!tmp)
                    continue;
                // ~T(%tmp)（1 参）或 reset(&%tmp, null/0)（2 参，clang 把 inline 后
                // 的 ~unique_ptr 降级成 reset(nullptr)）。第 2 个及以后的参数必须是
                // 常量 0/null（reset 的"清空"实参），避免误伤 reset(new_ptr) 这类。
                bool constTail = true;
                for (unsigned i = 1; i < dtor->arg_size(); ++i) {
                    if (!isa<Constant>(dtor->getArgOperand(i))) {
                        constTail = false;
                        break;
                    }
                }
                if (!constTail)
                    continue;

                // 只认 C++ 析构（mangling 含 D0/D1/D2）和 unique_ptr::reset(nullptr)
                // （含 "5reset"），避免把 void(ptr alloca, const) 形式的普通调用
                // （lambda operator()、构造 stub 等）误判为析构。
                StringRef cn = dtor->getCalledFunction()->getName();
                if (!(cn.starts_with("_Z") &&
                      (cn.contains("D0") || cn.contains("D1") ||
                       cn.contains("D2") || cn.contains("5reset"))))
                    continue;

                // 两条识别路径（详见函数头注释）：
                //   pathA：存在 call T::T(ptr %tmp, ptr %src) move-construct。
                //   pathB：size <= 8（兜底 -O1 已 inline 掉 move-ctor 的场景）。
                // 两条都要求 hasLoad（备份临时的值必被读出交给 callee）。
                bool hasMoveCtor = false;
                for (User *U : tmp->users()) {
                    auto *CI = dyn_cast<CallInst>(U);
                    if (CI && isMoveConstructOf(CI, tmp)) {
                        hasMoveCtor = true;
                        break;
                    }
                }

                bool hasLoad = false;
                for (User *U : tmp->users()) {
                    if (isa<LoadInst>(U)) {
                        hasLoad = true;
                        break;
                    }
                }
                if (!hasLoad)
                    continue;

                const DataLayout &DL = M.getDataLayout();
                uint64_t allocSize = DL.getTypeAllocSize(tmp->getAllocatedType());
                bool pathA = hasMoveCtor;
                bool pathB = (allocSize <= 8);
                if (!pathA && !pathB)
                    continue;

                // pathA 加 benign-use 守卫（避免误伤有 move-ctor 的普通局部对象）；
                // pathB 不加（已在 STL 测试集上验证不误伤，sret 传入等 use 也允许）。
                bool matched = false;
                if (pathA) {
                    bool benign = true;
                    for (User *U : tmp->users()) {
                        if (!isBenignTmpUse(tmp, U)) {
                            benign = false;
                            break;
                        }
                    }
                    if (benign)
                        matched = true;
                }
                if (!matched && pathB)
                    matched = true;
                if (!matched)
                    continue;

                toErase.push_back({tmp, dtor});
            }

            for (auto &[tmp, dtor] : toErase) {
                IRBuilder<> B(dtor);
                B.CreateStore(Constant::getNullValue(tmp->getAllocatedType()), tmp);
                changed = true;
            }
        }
    }

    return changed;
}

// ===========================================================================
// 变参函数（varargs）改写
//
// BPF 后端拒绝任何 isVarArg=true 的函数（BPFISelLowering::LowerFormalArguments
// 里 IsVarArg 检查直接 fail）。本路径把变参函数改写成定参，让后端见不到变参。
//
// ABI（clang 原生 void* 裸指针语义）：
//   callee：R f(T0..Tn, ...) -> R f(T0..Tn, ptr __va_base)
//          __va_base 指向 caller 构建的 vararg 内存区（第一个 vararg 的地址）。
//          函数体内 va_list（即 alloca ptr）经 va_start 后存 __va_base。
//   caller：每个 call site 在入口 alloca 一段内存，按变参实参类型布局填值，
//          传首地址作 __va_base。
//
// intrinsic lowering（callee 体内）：
//   va_start(%ap)：store ptr __va_base, ptr %ap   （va_list 指向第一个 vararg）
//   va_arg(%ap,T)：load T, ptr %ap; %next=gep i8,%ap,allocSize(T); store %next,%ap
//   va_end(%ap)  ：no-op
//   va_copy(%d,%s)：%t=load ptr,%s; store %t,%d   （拷贝裸指针值）
// ===========================================================================

// 替换函数体内的 va_start/va_arg/va_end/va_copy。
// VaBase 非 null 时（变参函数改写路径），va_start 绑定到 __va_base；
// VaBase 为 null 时（非变参函数，体内不会有 va_start，只有 va_copy/va_arg/va_end）。
// 返回是否有改动。
static bool lowerVaIntrinsics(Function &F, Value *VaBase) {
    // 先收集所有要处理的指令（边遍历边删不安全）。
    SmallVector<Instruction *, 16> toProcess;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (isa<VAStartInst>(I) || isa<VAEndInst>(I) ||
                isa<VACopyInst>(I) || isa<VAArgInst>(I))
                toProcess.push_back(&I);
        }
    }

    if (toProcess.empty())
        return false;

    const DataLayout &DL = F.getParent()->getDataLayout();

    // 收集 va_arg/va_copy 涉及的指针参数索引：lower 后会通过它们写回推进值，
    // 必须清除 clang 标记的 readonly/readnone/nocapture，否则后续优化器（instcombine）
    // 会把写回的 store 当死存储删掉（pop_arg 的 va_list 参数就因此丢失推进）。
    std::set<unsigned> mutatedArgIndices;
    auto record_arg = [&](Value *V) {
        if (auto *A = dyn_cast<Argument>(V))
            mutatedArgIndices.insert(A->getArgNo());
    };

    for (Instruction *I : toProcess) {
        IRBuilder<> B(I);

        if (auto *VAS = dyn_cast<VAStartInst>(I)) {
            // va_start(%ap)：让 va_list 变量（alloca ptr）存 __va_base。
            // 非变参函数里不应出现 va_start；若出现且无 VaBase 则保留原样（保守）。
            if (VaBase) {
                Value *ApList = VAS->getArgList();
                B.CreateStore(VaBase, ApList);
                I->eraseFromParent();
            }
        } else if (auto *VAA = dyn_cast<VAArgInst>(I)) {
            // va_arg(%ap, T)：VoidPtrBuiltinVaList 下，va_list 是 void*，va_arg 的指针
            // 操作数是「指向 va_list 的指针」(void**)——指向一个保存「当前数据指针」的
            // 可写槽。读出当前 cur、load T、按 allocSize(T) 推进 cur 并写回槽。
            //   CurPtr = *ApOp        // 当前数据指针
            //   Val    = *CurPtr      // 读 T
            //   *ApOp  = CurPtr+step  // 推进，下一次 va_arg 读下一个参数
            // 推进的 store 直接内联，不依赖外部 helper。
            Value *ApOp = VAA->getPointerOperand();
            Type *Ty = VAA->getType();
            Value *CurPtr = B.CreateLoad(PointerType::getUnqual(F.getContext()), ApOp,
                                         "__va.cur");
            Value *Val = B.CreateLoad(Ty, CurPtr, "__va.val");
            uint64_t Step = DL.getTypeAllocSize(Ty);
            Value *Next = B.CreatePtrAdd(CurPtr,
                                         ConstantInt::get(Type::getInt64Ty(F.getContext()), Step),
                                         "__va.next");
            B.CreateStore(Next, ApOp);
            record_arg(ApOp);
            I->replaceAllUsesWith(Val);
            I->eraseFromParent();
        } else if (dyn_cast<VAEndInst>(I)) {
            // va_end：no-op。
            I->eraseFromParent();
        } else if (auto *VAC = dyn_cast<VACopyInst>(I)) {
            // va_copy(%dst, %src)：拷贝裸指针值。
            Value *Dst = VAC->getDest();
            Value *Src = VAC->getSrc();
            Value *Tmp = B.CreateLoad(PointerType::getUnqual(F.getContext()), Src, "__va.cp");
            B.CreateStore(Tmp, Dst);
            record_arg(Dst);
            record_arg(Src);
            I->eraseFromParent();
        }
    }

    // 清除被写回参数的 readonly/readnone/nocapture：lower 后这些参数会被 store，
    // clang 原标的「不修改内存」属性已不成立，留着会让后续 instcombine 删掉推进 store。
    for (unsigned idx : mutatedArgIndices) {
        if (idx < F.arg_size()) {
            F.removeParamAttr(idx, Attribute::ReadOnly);
            F.removeParamAttr(idx, Attribute::ReadNone);
#if LLVM_VERSION_MAJOR < 21
            // LLVM 21 起 NoCapture 移除（并入 captures 语义），无需也无法 remove。
            F.removeParamAttr(idx, Attribute::NoCapture);
#endif
        }
    }
    // 函数级的 readonly/readnone 也得清（pop_arg 整体被标 readonly）。
    F.removeFnAttr(Attribute::ReadOnly);
    F.removeFnAttr(Attribute::ReadNone);
    return true;
}

// 改写一个变参函数：构造新签名（原具名参数 + 末尾 ptr __va_base）。
//   - 有函数体（定义）：搬迁函数体，把旧具名参数映射到新参数，lower 体内 va intrinsic。
//   - 纯声明（prototype）：只改签名（创建新声明），无 body 可搬/无 intrinsic 可 lower。
// 返回新 Function*（旧的会被 dropAllReferences，由 run() 统一删除）。
static Function *rewriteVarArgFunction(Function &F) {
    Module &M = *F.getParent();

    // -  构造新参数类型表：原具名参数原样 + 末尾一个 ptr（__va_base）。
    SmallVector<Type *, 8> newArgTys;
    for (unsigned i = 0; i < F.arg_size(); ++i)
        newArgTys.push_back(F.getFunctionType()->getParamType(i));
    newArgTys.push_back(PointerType::getUnqual(M.getContext()));

    FunctionType *newFTy = FunctionType::get(F.getReturnType(), newArgTys, false);

    // -  创建新函数（临时名，最后 takeName 拿回原名）。
    Function *NewF = Function::Create(
        newFTy, F.getLinkage(), F.getAddressSpace(),
        "__bpf_va_tmp_" + F.getName(), &M);

    NewF->copyAttributesFrom(&F);
    NewF->setVisibility(F.getVisibility());
    NewF->setComdat(F.getComdat());
    NewF->setSection(F.getSection());
    NewF->setDSOLocal(F.isDSOLocal());

    if (F.isDeclaration()) {
        // 纯声明：只改签名，无 body 可搬。
        NewF->takeName(&F);
        F.dropAllReferences();
        return NewF;
    }

    // -  搬迁函数体。
    NewF->splice(NewF->end(), &F);
    NewF->takeName(&F);

    // -  把旧具名参数映射到新参数（前 N 个一一对应）。
    //    新增的末尾参数 __va_base 留给 lowerVaIntrinsics 用。
    unsigned oldIdx = 0;
    for (Argument &OldArg : F.args()) {
        OldArg.replaceAllUsesWith(NewF->getArg(oldIdx));
        ++oldIdx;
    }

    // -  lower 体内所有 va intrinsic，用末尾参数作 __va_base。
    Value *VaBase = NewF->getArg(NewF->arg_size() - 1);
    lowerVaIntrinsics(*NewF, VaBase);

    F.dropAllReferences();
    return NewF;
}

// 改写变参调用点的逻辑已统一到 rewriteCallSitePacked（Threshold = NumNamed），
// 故此处不再需要单独的 rewriteVarArgCallSite。

struct BpfWideArgsPass : PassInfoMixin<BpfWideArgsPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        bool changed = false;

        // sret 剥离 / i128 返回值降级 / 聚合值参数归一化。独立于 >5 参数处理，可叠加。
        changed |= stripSret(M);
        changed |= lowerI128Returns(M);
        changed |= lowerAggregateParams(M);

        // 改写 callee 签名与函数体（>5 参数 + 变参两条互斥路径），得到 {旧F->新F}。
        // 调用点改写推迟到下一阶段统一处理（让混合 caller 共用单块缓冲区）。
        struct ToRewrite { Function *F; Function *NewF; };
        SmallVector<ToRewrite, 16> work;
        for (Function &F : M) {
            if (!needsRewrite(F))
                continue;
            StructType *PackTy = buildPackType(F);
            work.push_back({&F, rewriteFunction(F, PackTy)});
            changed = true;
        }
        SmallVector<ToRewrite, 16> vaWork;
        for (Function &F : M) {
            if (!isVarArgFunction(F))
                continue;
            vaWork.push_back({&F, rewriteVarArgFunction(F)});
            changed = true;
        }

        // 调用点改写。同一 caller 的所有调用点（>5 参数 + 变参混合）共用入口块一块
        // 缓冲区：每个调用点发起 call 前从偏移 0 完整覆写，call 返回后即不再使用，
        // 窗口互不重叠。这样把"每调用点独立 alloca"导致的栈膨胀压缩为每 caller 单个
        // alloca。间接调用点（collectIndirectCallSites 独立扫描）即使 work/vaWork 空
        // 也要改，故本阶段无条件执行。
        {
            const DataLayout &DL = M.getDataLayout();
            SiteMap byCaller;
            BytesMap maxBytes;

            for (auto &w : work)
                collectCallSites(w.F, w.NewF, KEEP_REGS, DL, byCaller, maxBytes);
            for (auto &w : vaWork)
                collectCallSites(w.F, w.NewF, w.NewF->arg_size() - 1, DL,
                                 byCaller, maxBytes);
            collectIndirectCallSites(M, DL, byCaller, maxBytes);

            for (auto &[Caller, sites] : byCaller) {
                AllocaInst *SharedBuf = nullptr;
                bool anyPack = false;
                for (PackSite &s : sites)
                    if (!s.IsSyscall) { anyPack = true; break; }
                if (anyPack)
                    SharedBuf = allocSharedPackBuf(Caller, maxBytes[Caller]);
                for (PackSite &s : sites) {
                    if (s.IsSyscall)
                        rewriteCallSiteSyscall6(s.CB, s.Callee);
                    else
                        rewriteCallSitePacked(s.CB, s.Callee, SharedBuf,
                                             s.Threshold);
                }
            }
        }

        // 旧 F 可能仍被取地址（存函数指针/函数指针表）等非 CallBase 引用。重定向到
        // NewF 的 bitcast，使 IR 合法可安全删除，且让间接调用命中 NewF 的新 ABI。
        auto rewriteStrayUses = [](Function *OldF, Function *NewF, const char *tag) {
            if (OldF->use_empty())
                return;
            errs() << "BpfWideArgs: note: " << NewF->getName()
                   << " had " << tag
                   << " uses (address-taken); redirected them to the rewritten "
                      "symbol (indirect calls are auto-rewritten to the new ABI)\n";
            PointerType *OldPtrTy = OldF->getType();
            Constant *Alias = ConstantExpr::getBitCast(NewF, OldPtrTy);
            OldF->replaceAllUsesWith(Alias);
        };
        for (auto &w : work) {
            rewriteStrayUses(w.F, w.NewF, "direct-arg");
            w.F->eraseFromParent();
        }
        for (auto &w : vaWork) {
            rewriteStrayUses(w.F, w.NewF, "vararg");
            w.F->eraseFromParent();
        }

        // 非变参函数（如 vfprintf，接收 va_list 参数）体内也可能有 va_copy/va_arg/
        // va_end，残留的 va intrinsic 会让 ISel 报 "Cannot select"。对模块所有函数
        //（含上面改写出的 NewF，对它们幂等）统一 lower；VaBase=null（无 va_start）。
        for (Function &F : M) {
            if (F.isDeclaration() || isInternalOrIntrinsic(F))
                continue;
            changed |= lowerVaIntrinsics(F, nullptr);
        }

        return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

    static bool isRequired() { return true; }   // -O0 也跑
};

// ===========================================================================
// VLA / 动态 alloca 改写（BpfVlaPass）。
//
// BPF 后端在 ISel 阶段拒绝动态栈分配（"unsupported dynamic stack allocation"），
// 也不接受非入口块的固定大小 alloca（BPF 要求所有 alloca 集中入口块）。本 pass
// 把这类 alloca 改写成对 BPF_SYS_ALLOCA syscall 的调用（VM 在栈帧上分配）。
//
// clang 把 VLA 编码为三件套，映射到 alloca(inc) syscall（inc 带符号：>0 扩展、
// =0 读当前下界、<0 收缩；返回调整后的下界 = 新块起始地址）：
//   动态 alloca Ty, %n（或固定大小但非入口块的）-> alloca(((n*sizeof)+15)&~15)
//     字节数向上对齐 16，保证相邻块间隔 16、每块起始相对 r10 偏移 16 对齐。
//   @llvm.stacksave -> alloca(0)：返回当前下界作退出时回退的 token。
//   @llvm.stackrestore(tok) -> alloca(tok - alloca(0))：当前下界与 token 的差
//     作收缩量（负值）。clang 在 VLA 块每个退出点都放了 stackrestore，逐个替换。
//
// 跑在 OptimizerLastEP：必须在 SROA/instcombine 之后（让固定 alloca 先被消除，
// 只改写漏网的动态/非入口块），在 CodeGen 之前。

// 构造一次 BPF syscall 调用：call <ptr> inttoptr(i64 <CallId> to ptr)(Args...)。
// 返回值类型按 RetTy 处理（BPF syscall 结果在 r0，整数/指针皆为 i64）。
static Value *emitVlaSyscall(IRBuilder<> &B, LLVMContext &Ctx, uint64_t CallId,
                             ArrayRef<Value *> Args, Type *RetTy) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    // LLVM 15+ 默认 opaque pointer，函数指针类型即 ptr（地址空间 0）。
    Type *PtrTy = PointerType::get(Ctx, 0);

    // 入参全部 zext 到 i64（BPF 寄存器 64 位；指针/size_t 即 i64）。
    SmallVector<Value *, 4> I64Args;
    for(Value *A : Args) {
        if(A->getType()->isIntegerTy() && A->getType()->getIntegerBitWidth() < 64)
            A = B.CreateZExt(A, I64Ty);
        I64Args.push_back(A);
    }

    // 函数类型：RetTy(I64...)。统一用 i64 入参；返回值用 RetTy（i64 或 ptr）。
    SmallVector<Type *, 4> ArgTys(I64Args.size(), I64Ty);
    Type *EffRetTy = RetTy->isPointerTy() ? I64Ty : RetTy;
    FunctionType *FTy = FunctionType::get(EffRetTy, ArgTys, false);

    // inttoptr(const CallId) 当作函数指针直接调用 -> 后端 emit `call <imm>`。
    Value *FnPtr = B.CreateIntToPtr(ConstantInt::get(I64Ty, CallId), PtrTy);
    Value *Call = B.CreateCall(FTy, FnPtr, I64Args);

    // 指针类型结果：i64 -> ptr（inttoptr）。整数窄类型：trunc。
    if(RetTy->isPointerTy())
        return B.CreateIntToPtr(Call, RetTy);
    if(RetTy->isIntegerTy() && RetTy->getIntegerBitWidth() < 64)
        return B.CreateTrunc(Call, RetTy);
    return Call;
}

// 处理单个函数：扫描所有动态 alloca 与 stacksave/stackrestore intrinsic，改写之。
static bool rewriteVla(Function &F) {
    LLVMContext &Ctx = F.getContext();
    Type *I64Ty = Type::getInt64Ty(Ctx);
    bool Changed = false;
    SmallVector<Instruction *, 16> ToErase;

    // 改写动态 alloca + 非入口块的固定大小 alloca。入口块的常量大小 alloca（标准
    // static alloca）BPF 能处理，不动。优化器有时把编译期已知大小的 VLA 折叠成固定
    // alloca 但留在循环/中间块（VLA 指针逃逸到未内联函数时），后端照样拒绝。
    BasicBlock *Entry = &F.getEntryBlock();
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            AllocaInst *AI = dyn_cast<AllocaInst>(&I);
            if(!AI) continue;

            Value *ArraySize = AI->getArraySize();
            bool isDynamicSize = ArraySize && !isa<ConstantInt>(ArraySize);
            bool isStaticInEntry = (&BB == Entry) && !isDynamicSize;
            if(isStaticInEntry) continue;

            // 总字节数 = 元素数 * 元素大小，向上对齐 16（相邻块间隔 16，起始相对
            // r10 偏移 16 对齐）。
            IRBuilder<> B(AI);
            Type *ElemTy = AI->getAllocatedType();
            const DataLayout &DL = F.getParent()->getDataLayout();
            uint64_t ElemSize = DL.getTypeAllocSize(ElemTy);
            Value *Count;
            if(!ArraySize)
                Count = ConstantInt::get(I64Ty, 1);
            else
                Count = B.CreateZExt(ArraySize, I64Ty);
            Value *Bytes = Count;
            if(ElemSize != 1) {
                Value *SizeVal = ConstantInt::get(I64Ty, ElemSize);
                Bytes = B.CreateMul(Bytes, SizeVal, "vla.bytes");
            }
            Constant *Fifteen = ConstantInt::get(I64Ty, 15);
            Constant *InvMask = ConstantInt::get(I64Ty, ~(uint64_t)15);
            Bytes = B.CreateAnd(B.CreateAdd(Bytes, Fifteen), InvMask,
                                "vla.aligned");

            Value *Ptr = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Bytes},
                                        AI->getType());
            AI->replaceAllUsesWith(Ptr);
            ToErase.push_back(AI);
            Changed = true;
        }
    }

    // stacksave/stackrestore。stacksave -> alloca(0) 返回当前下界作 token；
    // stackrestore(tok) -> alloca(tok - alloca(0))：栈向低地址生长，下界 = r10 -
    // total_len，stacksave 时 tok 较高（total_len 小），此时 cur 较低（期间做过
    // alloca），inc = cur - tok = save_total - cur_total < 0，收缩回 tok。
    // clang 在 VLA 块每个退出点都放了 stackrestore，逐个替换即可。
    Constant *Zero = ConstantInt::get(I64Ty, 0);
    for(BasicBlock &BB : F) {
        for(Instruction &I : BB) {
            IntrinsicInst *II = dyn_cast<IntrinsicInst>(&I);
            if(!II) continue;
            Intrinsic::ID ID = II->getIntrinsicID();

            if(ID == Intrinsic::stacksave) {
                IRBuilder<> B(II);
                Value *Tok = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Zero},
                                            II->getType());
                II->replaceAllUsesWith(Tok);
                ToErase.push_back(II);
                Changed = true;
            } else if(ID == Intrinsic::stackrestore) {
                IRBuilder<> B(II);
                Value *TokPtr = II->getArgOperand(0);
                Value *TokI = B.CreatePtrToInt(TokPtr, I64Ty, "alloca.tok");
                Value *Cur  = emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Zero}, I64Ty);
                Value *Inc  = B.CreateSub(Cur, TokI, "alloca.inc");
                emitVlaSyscall(B, Ctx, BPF_CALL_ALLOCA, {Inc}, I64Ty);
                II->replaceAllUsesWith(UndefValue::get(I.getType()));
                ToErase.push_back(II);
                Changed = true;
            }
        }
    }

    for(Instruction *I : ToErase)
        I->eraseFromParent();

    return Changed;
}

class BpfVlaPass : public PassInfoMixin<BpfVlaPass> {
public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if(F.isDeclaration())
            return PreservedAnalyses::all();
        return rewriteVla(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
};

// by-value 非平凡析构参数 double-free 修复（见上）。两个 EP 都跑：
//  PipelineStartEP（紧跟 BpfWideArgsPass）：-O1 之前清零备份临时，否则 -O1 会把它
//    与源对象 fold，把 caller 析构直接 fold 成对原 ctrl 的 atomicrmw -1（miscompile）。
//  OptimizerLastEP：兜底 -O1 已把 move-construct inline 成 store 的场景。
class BpfByvalTmpPass : public PassInfoMixin<BpfByvalTmpPass> {
public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        return eliminateByvalScalarTemporaries(M)
                   ? PreservedAnalyses::none()
                   : PreservedAnalyses::all();
    }
    static bool isRequired() { return true; }
};

// atomic load/store 降级（解锁 iostream/locale 等的 static guard、OpenSSL threads）。
// eBPF ISA 只有 RMW 类原子指令，没有独立的 plain atomic load/store（LLVM 21 才补
// BPF_LOAD_ACQ/BPF_STORE_REL，本项目用 LLVM 19）。三类处理：
//   - LoadInst/StoreInst 的 atomic 形式 -> 普通非原子 load/store。
//   - i8/i16 的 AtomicRMW/CmpXchg -> 展开成对包含它的对齐 i32 槽的子字节 CAS 循环
//    （后端只支持 i32/i64；照搬 LLVM expandPartwordAtomicRMW/CmpXchg）。解锁
//     atomic<bool>/char/short。子字节展开先于 load/store 降级，否则它插入的普通
//     load 会被再降级。
//   - atomic_thread_fence -> 直接删（BPF 无 fence 指令；单线程顺序执行下是空操作）。
//   i32/i64 的 RMW/cmpxchg 不动（后端原生支持）。
// 降级 plain atomic load 正确性依据：VM 单线程，guard 的 slow path __cxa_guard_acquire
// 本就是非原子实现（_LIBCPP_HAS_NO_THREADS），fast-path 那处原子是孤立的。
class BpfAtomicLowerPass : public PassInfoMixin<BpfAtomicLowerPass> {
    // 子字节 CAS 的 mask/shift 计算结果（对应 LLVM PartwordMaskValues）。
    struct PartwordMaskValues {
        Type *WordType = nullptr;        // 展开后的宽类型（i32）
        Value *AlignedAddr = nullptr;    // 对齐到 WordSize 的地址（addr & ~(WS-1)）
        Align AlignedAddrAlignment;      // 对齐值（= WordSize）
        Value *ShiftAmt = nullptr;       // 目标字节的位偏移（PtrLSB * 8）
        Value *Mask = nullptr;           // 目标字节在宽槽里的位掩码
        Value *Inv_Mask = nullptr;       // 反掩码（清目标字节用）
    };

    static constexpr unsigned MinWordSize = 4;  // BPF 原子最小宽度（i32）

    // 窄原子子字节 CAS 的前提：对象位于一个可安全 4 字节读写的槽内（AlignedAddr 处
    // 的 i32 load/store 不能越界破坏相邻对象）。对 _Atomic 全局/堆对象成立（标准要求
    // 对齐）；但栈上窄 atomic（如局部 uint16_t）clang 只给 align=2 的 alloca，&s & ~3
    // 会越过对象边界读到/写脏相邻栈数据。
    // 修复：把窄 atomic 指针背后的 alloca 对齐提升到 MinWordSize。提升后编译器给它
    // 分配 4 字节对齐的栈槽，&s & 3 == 0，shift=0，CAS 只在对象自身的 4 字节内（对象
    // 因 alloca 变大而获得额外 padding，不越界）。对非 alloca（堆/全局/参数）不动——
    // 它们的对齐由分配方保证，且 _Atomic 语义要求对象布局容纳原子访问。
    static void widenUnderlyingAllocaAlign(Value *Addr) {
        // 剥掉 bitcast / GEP（零偏移），找到底层 alloca。
        Value *U = Addr->stripPointerCasts();
        // 只处理「整个 alloca 的起始」（GEP 带偏移的不安全，无法靠提升对齐修复）。
        if(auto *AI = dyn_cast<AllocaInst>(U)) {
            if(AI->getAlign().value() < MinWordSize)
                AI->setAlignment(Align(MinWordSize));
        }
    }

    // 计算 addr/shift/mask（照搬 LLVM createMaskInstrs，简化：只处理整数小端）。
    static PartwordMaskValues createMaskInstrs(IRBuilder<> &Builder, Instruction *I,
                                                Type *ValueType, Value *Addr,
                                                Align AddrAlign) {
        PartwordMaskValues PMV;
        const DataLayout &DL = I->getModule()->getDataLayout();
        LLVMContext &Ctx = I->getContext();
        unsigned ValueSize = DL.getTypeStoreSize(ValueType);  // i8->1, i16->2
        PMV.WordType = Type::getInt32Ty(Ctx);
        PMV.AlignedAddrAlignment = Align(MinWordSize);

        PointerType *PtrTy = cast<PointerType>(Addr->getType());
        IntegerType *IntTy = DL.getIndexType(Ctx, PtrTy->getAddressSpace());
        Value *PtrLSB;
        if(AddrAlign < MinWordSize) {
            // 地址对齐不足：运行时对齐（ptrmask）+ 取低位算 shift。
            PMV.AlignedAddr = Builder.CreateIntrinsic(
                Intrinsic::ptrmask, {PtrTy, IntTy},
                {Addr, ConstantInt::get(IntTy, ~(uint64_t)(MinWordSize - 1))}, nullptr,
                "AlignedAddr");
            Value *AddrInt = Builder.CreatePtrToInt(Addr, IntTy);
            PtrLSB = Builder.CreateAnd(AddrInt, MinWordSize - 1, "PtrLSB");
        } else {
            // 已对齐：LSB 已知 0，shift=0。
            PMV.AlignedAddr = Addr;
            PtrLSB = ConstantInt::getNullValue(IntTy);
        }
        PMV.ShiftAmt = Builder.CreateTrunc(Builder.CreateShl(PtrLSB, 3), PMV.WordType,
                                            "ShiftAmt");
        PMV.Mask = Builder.CreateShl(
            ConstantInt::get(PMV.WordType, (1 << (ValueSize * 8)) - 1), PMV.ShiftAmt,
            "Mask");
        PMV.Inv_Mask = Builder.CreateNot(PMV.Mask, "Inv_Mask");
        return PMV;
    }

    // 从宽槽里提取目标窄值（lshr + trunc）。
    static Value *extractMaskedValue(IRBuilder<> &Builder, Value *WideWord, Type *ValueType,
                                      const PartwordMaskValues &PMV) {
        Value *Shift = Builder.CreateLShr(WideWord, PMV.ShiftAmt, "shifted");
        return Builder.CreateTrunc(Shift, ValueType, "extracted");
    }

    // D2a: i8/i16 cmpxchg -> i32 子字节 CAS loop（照搬 expandPartwordCmpXchg）。
    // IR 序列见 llvm/lib/CodeGen/AtomicExpandPass.cpp:1015 注释。
    static bool expandPartwordCmpXchg(AtomicCmpXchgInst *CI) {
        Value *Addr = CI->getPointerOperand();
        widenUnderlyingAllocaAlign(Addr);  // 提升栈窄 atomic 的对齐，避免越界
        Value *Cmp = CI->getCompareOperand();
        Value *NewVal = CI->getNewValOperand();
        Type *ValueType = Cmp->getType();

        BasicBlock *BB = CI->getParent();
        Function *F = BB->getParent();
        IRBuilder<> Builder(CI);
        BasicBlock *EndBB = BB->splitBasicBlock(CI->getIterator(), "partword.cmpxchg.end");
        BasicBlock *FailureBB = BasicBlock::Create(CI->getContext(),
                                                    "partword.cmpxchg.failure", F, EndBB);
        BasicBlock *LoopBB = BasicBlock::Create(CI->getContext(),
                                                 "partword.cmpxchg.loop", F, FailureBB);
        std::prev(BB->end())->eraseFromParent();  // 去掉 split 加的错分支
        Builder.SetInsertPoint(BB);

        PartwordMaskValues PMV = createMaskInstrs(Builder, CI, ValueType, Addr, CI->getAlign());
        Value *NewVal_Shifted = Builder.CreateShl(Builder.CreateZExt(NewVal, PMV.WordType),
                                                   PMV.ShiftAmt);
        Value *Cmp_Shifted = Builder.CreateShl(Builder.CreateZExt(Cmp, PMV.WordType),
                                                PMV.ShiftAmt);
        LoadInst *InitLoaded = Builder.CreateLoad(PMV.WordType, PMV.AlignedAddr);
        InitLoaded->setVolatile(CI->isVolatile());
        Value *InitLoaded_MaskOut = Builder.CreateAnd(InitLoaded, PMV.Inv_Mask);
        Builder.CreateBr(LoopBB);

        // loop:
        Builder.SetInsertPoint(LoopBB);
        PHINode *Loaded_MaskOut = Builder.CreatePHI(PMV.WordType, 2);
        Loaded_MaskOut->addIncoming(InitLoaded_MaskOut, BB);
        Value *FullWord_NewVal = Builder.CreateOr(Loaded_MaskOut, NewVal_Shifted);
        Value *FullWord_Cmp = Builder.CreateOr(Loaded_MaskOut, Cmp_Shifted);
        AtomicCmpXchgInst *NewCI = Builder.CreateAtomicCmpXchg(
            PMV.AlignedAddr, FullWord_Cmp, FullWord_NewVal, PMV.AlignedAddrAlignment,
            CI->getSuccessOrdering(), CI->getFailureOrdering(), CI->getSyncScopeID());
        NewCI->setVolatile(CI->isVolatile());
        NewCI->setWeak(CI->isWeak());
        Value *OldVal = Builder.CreateExtractValue(NewCI, 0);
        Value *Success = Builder.CreateExtractValue(NewCI, 1);
        if(CI->isWeak())
            Builder.CreateBr(EndBB);
        else
            Builder.CreateCondBr(Success, EndBB, FailureBB);

        // failure: 周边位变了才重试，否则真实失败。
        Builder.SetInsertPoint(FailureBB);
        Value *OldVal_MaskOut = Builder.CreateAnd(OldVal, PMV.Inv_Mask);
        Value *ShouldContinue = Builder.CreateICmpNE(Loaded_MaskOut, OldVal_MaskOut);
        Builder.CreateCondBr(ShouldContinue, LoopBB, EndBB);
        Loaded_MaskOut->addIncoming(OldVal_MaskOut, FailureBB);

        // end: 提取旧值，重组 {窄值, i1} 返回。
        Builder.SetInsertPoint(CI);
        Value *FinalOldVal = extractMaskedValue(Builder, OldVal, ValueType, PMV);
        Value *Res = PoisonValue::get(CI->getType());
        Res = Builder.CreateInsertValue(Res, FinalOldVal, 0);
        Res = Builder.CreateInsertValue(Res, Success, 1);
        CI->replaceAllUsesWith(Res);
        CI->eraseFromParent();
        return true;
    }

    // 算 RMW 在【窄值原宽】下的 new value（Min/Max 等需原宽比较）。
    static Value *buildRMWValue(AtomicRMWInst::BinOp Op, IRBuilder<> &B,
                                 Value *Loaded, Value *Inc) {
        switch(Op) {
        case AtomicRMWInst::Xchg: return Inc;
        case AtomicRMWInst::Add:  return B.CreateAdd(Loaded, Inc, "new");
        case AtomicRMWInst::Sub:  return B.CreateSub(Loaded, Inc, "new");
        case AtomicRMWInst::And:  return B.CreateAnd(Loaded, Inc, "new");
        case AtomicRMWInst::Nand: return B.CreateNot(B.CreateAnd(Loaded, Inc), "new");
        case AtomicRMWInst::Or:   return B.CreateOr(Loaded, Inc, "new");
        case AtomicRMWInst::Xor:  return B.CreateXor(Loaded, Inc, "new");
        case AtomicRMWInst::Max:  return B.CreateSelect(B.CreateICmpSGT(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::Min:  return B.CreateSelect(B.CreateICmpSLE(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::UMax: return B.CreateSelect(B.CreateICmpUGT(Loaded, Inc), Loaded, Inc, "new");
        case AtomicRMWInst::UMin: return B.CreateSelect(B.CreateICmpULE(Loaded, Inc), Loaded, Inc, "new");
        default: return nullptr;  // FP/UIncWrap/UDecWrap 不处理（窄场景无意义）
        }
    }

    // D2b: i8/i16 atomicrmw -> i32 子字节 CAS loop（照搬 expandPartwordAtomicRMW）。
    // Or/Xor/And 直接 widen 成 i32 原子位运算（周边位为 0/1 不影响结果；And 需把
    //   非目标字节置 1 避免清掉）。Add/Sub/Nand 在移位后的位上算再 mask 回目标字节。
    //   Min/Max/UMin/UMax extract 出窄值原宽算再 insert 回宽槽。
    static bool expandPartwordRMW(AtomicRMWInst *AI) {
        AtomicRMWInst::BinOp Op = AI->getOperation();
        Type *ValueType = AI->getType();
        Value *Addr = AI->getPointerOperand();
        widenUnderlyingAllocaAlign(Addr);  // 提升栈窄 atomic 的对齐，避免越界
        AtomicOrdering MemOpOrder = AI->getOrdering();
        SyncScope::ID SSID = AI->getSyncScopeID();
        IRBuilder<> Builder(AI);

        PartwordMaskValues PMV = createMaskInstrs(Builder, AI, ValueType, Addr, AI->getAlign());

        // 分支 1: Or/Xor/And widen 成 i32 原子位运算（不需 CAS loop）。
        if(Op == AtomicRMWInst::Or || Op == AtomicRMWInst::Xor || Op == AtomicRMWInst::And) {
            Value *ValOperand_Shifted = Builder.CreateShl(
                Builder.CreateZExt(AI->getValOperand(), PMV.WordType), PMV.ShiftAmt,
                "ValOperand_Shifted");
            Value *NewOperand = (Op == AtomicRMWInst::And)
                                    ? Builder.CreateOr(ValOperand_Shifted, PMV.Inv_Mask, "AndOperand")
                                    : ValOperand_Shifted;
            AtomicRMWInst *NewAI = Builder.CreateAtomicRMW(Op, PMV.AlignedAddr, NewOperand,
                                                            PMV.AlignedAddrAlignment, MemOpOrder, SSID);
            Value *FinalOld = extractMaskedValue(Builder, NewAI, ValueType, PMV);
            AI->replaceAllUsesWith(FinalOld);
            AI->eraseFromParent();
            return true;
        }

        // 分支 2/3: CAS loop（在移位后的位上算，或 extract 后原宽算）。
        // 预计算移位后的 incr（Add/Sub/Nand/Xchg 用；Min/Max 等用原宽 Inc）。
        Value *ValOperand_Shifted = nullptr;
        if(Op == AtomicRMWInst::Xchg || Op == AtomicRMWInst::Add ||
           Op == AtomicRMWInst::Sub || Op == AtomicRMWInst::Nand) {
            ValOperand_Shifted = Builder.CreateShl(
                Builder.CreateZExt(AI->getValOperand(), PMV.WordType), PMV.ShiftAmt,
                "ValOperand_Shifted");
        }

        // PerformOp: 给定当前宽槽值 Loaded，算要 CAS 进去的 FullWord。
        auto PerformOp = [&](IRBuilder<> &B, Value *Loaded) -> Value * {
            switch(Op) {
            case AtomicRMWInst::Xchg: {
                Value *Loaded_MaskOut = B.CreateAnd(Loaded, PMV.Inv_Mask);
                return B.CreateOr(Loaded_MaskOut, ValOperand_Shifted);
            }
            case AtomicRMWInst::Add:
            case AtomicRMWInst::Sub:
            case AtomicRMWInst::Nand: {
                Value *NewVal = buildRMWValue(Op, B, Loaded, ValOperand_Shifted);
                Value *NewVal_Masked = B.CreateAnd(NewVal, PMV.Mask);
                Value *Loaded_MaskOut = B.CreateAnd(Loaded, PMV.Inv_Mask);
                return B.CreateOr(Loaded_MaskOut, NewVal_Masked);
            }
            case AtomicRMWInst::Max: case AtomicRMWInst::Min:
            case AtomicRMWInst::UMax: case AtomicRMWInst::UMin: {
                Value *Loaded_Extract = extractMaskedValue(B, Loaded, ValueType, PMV);
                Value *NewVal = buildRMWValue(Op, B, Loaded_Extract, AI->getValOperand());
                if(!NewVal) return nullptr;
                Value *ZExt = B.CreateZExt(NewVal, PMV.WordType, "extended");
                Value *Shift = B.CreateShl(ZExt, PMV.ShiftAmt, "shifted", /*HasNUW*/ true);
                Value *And = B.CreateAnd(Loaded, PMV.Inv_Mask, "unmasked");
                return B.CreateOr(And, Shift, "inserted");
            }
            default:
                return nullptr;
            }
        };

        // 构造 CAS loop（照搬 insertRMWCmpXchgLoop）。
        BasicBlock *BB = Builder.GetInsertBlock();
        Function *F = BB->getParent();
        BasicBlock *ExitBB = BB->splitBasicBlock(Builder.GetInsertPoint(), "atomicrmw.end");
        BasicBlock *LoopBB = BasicBlock::Create(AI->getContext(), "atomicrmw.start", F, ExitBB);
        std::prev(BB->end())->eraseFromParent();
        Builder.SetInsertPoint(BB);
        LoadInst *InitLoaded = Builder.CreateLoad(PMV.WordType, PMV.AlignedAddr);
        Builder.CreateBr(LoopBB);

        Builder.SetInsertPoint(LoopBB);
        PHINode *Loaded = Builder.CreatePHI(PMV.WordType, 2, "loaded");
        Loaded->addIncoming(InitLoaded, BB);
        Value *NewVal = PerformOp(Builder, Loaded);
        AtomicOrdering CmpOrder = (MemOpOrder == AtomicOrdering::Unordered)
                                      ? AtomicOrdering::Monotonic : MemOpOrder;
        AtomicCmpXchgInst *Pair = Builder.CreateAtomicCmpXchg(
            PMV.AlignedAddr, Loaded, NewVal, PMV.AlignedAddrAlignment, CmpOrder,
            AtomicCmpXchgInst::getStrongestFailureOrdering(CmpOrder), SSID);
        Value *NewLoaded = Builder.CreateExtractValue(Pair, 0);
        Value *Success = Builder.CreateExtractValue(Pair, 1);
        Loaded->addIncoming(NewLoaded, LoopBB);
        Builder.CreateCondBr(Success, ExitBB, LoopBB);

        Builder.SetInsertPoint(ExitBB, ExitBB->begin());
        Value *FinalOld = extractMaskedValue(Builder, NewLoaded, ValueType, PMV);
        AI->replaceAllUsesWith(FinalOld);
        AI->eraseFromParent();
        return true;
    }

public:
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if(F.isDeclaration())
            return PreservedAnalyses::all();

        bool Changed = false;
        SmallVector<LoadInst *, 16> Loads;
        SmallVector<StoreInst *, 16> Stores;
        SmallVector<AtomicCmpXchgInst *, 16> NarrowCmpXchgs;
        SmallVector<AtomicRMWInst *, 16> NarrowRMWs;
        SmallVector<FenceInst *, 16> Fences;
        for(BasicBlock &BB : F) {
            for(Instruction &I : BB) {
                if(auto *LI = dyn_cast<LoadInst>(&I)) {
                    if(LI->isAtomic())
                        Loads.push_back(LI);
                } else if(auto *SI = dyn_cast<StoreInst>(&I)) {
                    if(SI->isAtomic())
                        Stores.push_back(SI);
                } else if(auto *CmpX = dyn_cast<AtomicCmpXchgInst>(&I)) {
                    // 窄 cmpxchg（i8/i16）：BPF 后端只支持 i32/i64，需展开。
                    if(CmpX->getCompareOperand()->getType()->getIntegerBitWidth() < 32)
                        NarrowCmpXchgs.push_back(CmpX);
                } else if(auto *RMW = dyn_cast<AtomicRMWInst>(&I)) {
                    // 窄 RMW：同上。跳过浮点（BPF 无窄浮点原子场景）。
                    if(!RMW->isFloatingPointOperation() &&
                       RMW->getType()->getIntegerBitWidth() < 32)
                        NarrowRMWs.push_back(RMW);
                } else if(isa<FenceInst>(&I)) {
                    // D3: atomic_thread_fence -> 删除（见下文 D3 段）。
                    Fences.push_back(cast<FenceInst>(&I));
                }
            }
        }

        // D3: atomic_thread_fence（任意 ordering）-> 直接删除。
        // BPF 后端无 fence 指令（eBPF ISA 只有 RMW 原子 lock_xadd/xchg/cmpxchg，无独立
        // 内存屏障），ISel 对 AtomicFence 节点报 "Cannot select"。本 VM 单线程顺序执行
        // guest 指令，RMW 原子本身已带全屏障语义，跨线程同步靠 futex（do_futex 的
        // g_futex_mutex 提供顺序），fence 在 IR 层是无操作的空壳。fence 无返回值、无 user，
        // eraseFromParent 即可。解锁 OpenSSL threads 模式（BIO_free 等引用计数路径的
        // __atomic_thread_fence）。
        for(FenceInst *FI : Fences) {
            FI->eraseFromParent();
            Changed = true;
        }

        // D2 先展开窄原子（会插入普通 load，不该被 D1 再降级）。
        for(AtomicCmpXchgInst *CmpX : NarrowCmpXchgs) {
            expandPartwordCmpXchg(CmpX);
            Changed = true;
        }
        for(AtomicRMWInst *RMW : NarrowRMWs) {
            expandPartwordRMW(RMW);
            Changed = true;
        }

        // D1: load atomic T, ptr <order>, align A  ->  load T, ptr, align A
        // 直接构造普通 LoadInst（IRBuilder 的 CreateLoad 无带 Align 的重载），
        // 复制对齐/volatile/调试元数据，order 设为 NotAtomic，插在原指令前再替换。
        for(LoadInst *LI : Loads) {
            LoadInst *New = new LoadInst(LI->getType(), LI->getPointerOperand(), "",
                                          LI->isVolatile(), LI->getAlign(),
                                          LI->getIterator());
            New->setOrdering(AtomicOrdering::NotAtomic);
            if(LI->hasMetadata())
                New->setMetadata(LLVMContext::MD_dbg, LI->getMetadata(LLVMContext::MD_dbg));
            LI->replaceAllUsesWith(New);
            LI->eraseFromParent();
            Changed = true;
        }

        // D1: store atomic T v, ptr <order>, align A  ->  store T v, ptr, align A
        for(StoreInst *SI : Stores) {
            StoreInst *New = new StoreInst(SI->getValueOperand(), SI->getPointerOperand(),
                                            SI->isVolatile(), SI->getAlign(),
                                            SI->getIterator());
            New->setOrdering(AtomicOrdering::NotAtomic);
            if(SI->hasMetadata())
                New->setMetadata(LLVMContext::MD_dbg, SI->getMetadata(LLVMContext::MD_dbg));
            SI->eraseFromParent();
            Changed = true;
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
    static bool isRequired() { return true; }
};

} // namespace

// ---- 插件注册 ----
// 各 pass 挂在其需要的 pipeline EP（时机原因见各 pass 注释）：
//   BpfWideArgsPass   PipelineStartEP（早，所有 -O 触发）+ 下方 -O0 兜底
//   BpfByvalTmpPass   PipelineStartEP（紧跟 WideArgs）+ OptimizerLastEP（兜底）
//   BpfVlaPass        OptimizerLastEP + 下方 -O0 兜底
//   BpfAtomicLowerPass OptimizerLastEP + 下方 -O0 兜底
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfWideArgs", LLVM_VERSION_STRING, [](PassBuilder &PB) {
        PB.registerPipelineStartEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel) {
                MPM.addPass(BpfWideArgsPass());
                // ByvalTmp 早跑一份：必须在 -O1 之前清零备份临时（详见 BpfByvalTmpPass）。
                MPM.addPass(BpfByvalTmpPass());
            });

        auto addVlaPass = [](ModulePassManager &MPM) {
            FunctionPassManager FPM;
            FPM.addPass(BpfVlaPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        };
        auto addByvalTmpPass = [](ModulePassManager &MPM) {
            MPM.addPass(BpfByvalTmpPass());
        };
        auto addAtomicLowerPass = [](ModulePassManager &MPM) {
            FunctionPassManager FPM;
            FPM.addPass(BpfAtomicLowerPass());
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
        };
        PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR >= 21
            [addVlaPass, addByvalTmpPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
#else
            [addVlaPass, addByvalTmpPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel) {
#endif
                addVlaPass(MPM);
                addByvalTmpPass(MPM);
                addAtomicLowerPass(MPM);
            });
        // -O0 不经 OptimizerLastEP，在 PipelineStartEP 补一份 VLA/AtomicLower（仅 O0）。
        PB.registerPipelineStartEPCallback(
            [addVlaPass, addAtomicLowerPass](ModulePassManager &MPM, OptimizationLevel OL) {
                if(OL == OptimizationLevel::O0) {
                    addVlaPass(MPM);
                    addAtomicLowerPass(MPM);
                }
            });
    }};
}
