//===- BpfEmutls.cpp - emutls via annotate("emutls") ---------------------===//
//
// 为 BPF 目标提供 thread_local 支持。机制总览见 README「模拟 TLS (emutls)」；
// 运行时在 musl 的 src/thread/bpf/emutls.c。
//
// 预处理期 -Dthread_local='__attribute__((annotate("emutls")))' 把 thread_local
// 关键字替换成 annotate 属性（早于 Sema，绕过对 BPF thread_local 的拒绝）。本 pass
// 解析 @llvm.global.annotations 反查哪些全局是 emutls 变量，把对它们的访问改写成对
// 普通函数 __emutls_get_address 的调用，再访问其返回的每线程副本指针：
//   %p = call ptr @__emutls_get_address(ptr @__emutls_v.x)
//   load/store/GEP ... ptr %p
// 并为每个变量合成控制块 `@__emutls_v.<name> = {size, align, index, value*, dtor*}`。
//
// 用法：clang -target bpf -fpass-plugin=libBpfEmutls.so ...
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/ValueTracking.h" // getConstantStringInfo
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/CFG.h" // instructions()
#include "llvm/IR/Type.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// annotate("emutls") 的 annotation 字符串，见文件头说明。
constexpr const char *kEmutlsAnnot = "emutls";

// emutls 控制块布局（在 compiler-rt 基础上扩展 dtor 字段）：
//   { i64 size, i64 align, i64 index, ptr value, ptr dtor }
// index 初值 0（运行时懒分配）；value 为 null（零初始化）或指向初始化模板；
// dtor 为该变量的析构函数（平凡类型为 null），由 collectDtors 回填。两侧布局需与
// musl/src/thread/bpf/emutls.c 的 struct __emutls_control 严格一致。
StructType *getEmutlsControlType(LLVMContext &Ctx) {
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *Ptr = PointerType::get(Ctx, 0);
    return StructType::get(Ctx, {I64, I64, I64, Ptr, Ptr});
}

// 获取或声明 extern `ptr @__emutls_get_address(ptr)`。
// 这是普通函数调用（不走 FP 虚拟指令通道），由 musl 的 emutls.c 提供真实定义，
// 经 PLT/GOT 链路解析。入参为控制块指针，返回每线程副本地址——都是指针。
FunctionCallee declareEmutlsGetAddress(Module &M) {
    LLVMContext &Ctx = M.getContext();
    Type *Ptr = PointerType::get(Ctx, 0);
    // (ptr) -> ptr：直接用指针类型，无需 i64 位模式中转。
    FunctionType *FTy = FunctionType::get(Ptr, {Ptr}, false);
    FunctionCallee FC = M.getOrInsertFunction("__emutls_get_address", FTy);
    if (auto *F = dyn_cast<Function>(FC.getCallee())) {
        F->setLinkage(GlobalValue::ExternalLinkage);
    }
    return FC;
}

// 为一个 emutls 全局变量生成控制块 `@__emutls_v.<name>`（addrspace(0) 的 .data）。
// 有非零 initializer 时另生成模板全局 `@__emutls_t.<name>` 让 value 指向它。
// dtor 字段留 null，由 collectDtors 在控制块建好后用 setControlDtor 回填。
GlobalVariable *buildEmutlsControl(Module &M, GlobalVariable *GV) {
    LLVMContext &Ctx = M.getContext();
    Type *I64 = Type::getInt64Ty(Ctx);
    Type *Ptr = PointerType::get(Ctx, 0);

    // 原 GV 的元素类型（emutls 全局）。
    Type *ElemTy = GV->getValueType();
    const uint64_t Size = M.getDataLayout().getTypeAllocSize(ElemTy);
    const uint64_t Align = M.getDataLayout().getPrefTypeAlign(ElemTy).value();

    // value 指针：零初始化 -> null；非零 -> 新建模板全局 __emutls_t.<name>。
    Constant *ValueInit = ConstantPointerNull::get(cast<PointerType>(Ptr));
    Constant *GVInit = GV->getInitializer();
    bool isZeroInit = GVInit->isNullValue();
    if (!isZeroInit) {
        // 拷贝 initializer 到一个新的 addrspace(0) 模板全局。
        std::string TmplName = "__emutls_t." + GV->getName().str();
        auto *Tmpl = new GlobalVariable(
            M, ElemTy, /*isConstant*/ true, GlobalValue::InternalLinkage,
            GVInit, TmplName, nullptr, GlobalValue::NotThreadLocal, 0);
        Tmpl->setAlignment(M.getDataLayout().getPrefTypeAlign(ElemTy));
        ValueInit = ConstantExpr::getBitCast(Tmpl, Ptr);
    }

    // 控制块 initializer：{ size, align, index=0, value, dtor=null }（dtor 由 collectDtors 回填）。
    Constant *Null = ConstantPointerNull::get(cast<PointerType>(Ptr));
    Constant *CtrlInit = ConstantStruct::get(
        getEmutlsControlType(Ctx),
        {ConstantInt::get(I64, Size), ConstantInt::get(I64, Align),
         ConstantInt::get(I64, 0), ValueInit, Null});

    std::string CtrlName = "__emutls_v." + GV->getName().str();
    auto *Ctrl = new GlobalVariable(
        M, getEmutlsControlType(Ctx), /*isConstant*/ false,
        GlobalValue::InternalLinkage, CtrlInit, CtrlName, nullptr,
        GlobalValue::NotThreadLocal, 0);
    Ctrl->setAlignment(llvm::Align(8));
    return Ctrl;
}

// 把控制块的 dtor 字段回填为 Dtor。ConstantStruct initializer 无法原地改某字段，
// 需重新构造一个带新 dtor 的 initializer 整体替换。
void setControlDtor(GlobalVariable *Ctrl, Constant *Dtor) {
    auto *OldInit = cast<ConstantStruct>(Ctrl->getInitializer());
    Constant *DtorC = Dtor ? Dtor
        : ConstantPointerNull::get(cast<PointerType>(OldInit->getOperand(4)->getType()));
    Constant *NewInit = ConstantStruct::get(
        OldInit->getType(),
        {OldInit->getOperand(0), OldInit->getOperand(1), OldInit->getOperand(2),
         OldInit->getOperand(3), DtorC});
    Ctrl->setInitializer(NewInit);
}

// ModulePass：识别所有 emutls 全局，建控制块；改写所有对它们的访问（含函数内
// 取地址 &var 逃逸形式）为 __emutls_get_address 调用 + 普通指针解引用。
struct BpfEmutlsPass : public PassInfoMixin<BpfEmutlsPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        SmallVector<GlobalVariable *, 8> EmutlsGlobals;
        collectEmutlsGlobals(M, EmutlsGlobals);
        if (EmutlsGlobals.empty())
            return PreservedAnalyses::all();

        FunctionCallee GetAddr = declareEmutlsGetAddress(M);

        // 为每个 emutls 全局建控制块，记录映射。
        DenseMap<GlobalVariable *, GlobalVariable *> CtrlOf;
        for (GlobalVariable *GV : EmutlsGlobals)
            CtrlOf[GV] = buildEmutlsControl(M, GV);

        // 必须在 rewriteFunction 之前：检测不支持的使用形态（编译期硬错误），否则
        // 改写后这些 use 形态会变形，无法精确报错。
        checkUnsupportedForms(M, EmutlsGlobals);

        // 必须在 rewriteFunction 之前：从 init 函数里提取非平凡析构 thread_local 的
        // dtor 回填控制块并删除原 __cxa_atexit call。此时该 call 的 arg1（对象地址）仍
        // 是原始 emutls 全局，可据此反查控制块。
        collectDtors(M, CtrlOf);

        // 改写所有函数内对 emutls 全局的访问。
        bool Changed = false;
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
            Changed |= rewriteFunction(F, CtrlOf, GetAddr);
        }

        // 删除原 emutls 全局（数据已迁到控制块/模板）。@llvm.global.annotations 数组
        // 每个元素的 operand[0] 指向被标注的 GV，是一条活跃 use；该数组是 metadata
        //（section "llvm.metadata"），pass 识别完后不再需要，必须先整体 erase 掉，否则
        // GV.use_empty() 会因这条 use 返回 false，导致删不掉、最终 .o 残留死数据。
        if (GlobalVariable *Annot = M.getNamedGlobal("llvm.global.annotations"))
            Annot->eraseFromParent();
        for (GlobalVariable *GV : EmutlsGlobals) {
            // 改写过程中，引用 GV 的 ConstantExpr（如 gep(@arr,...)）在被指令
            // 替换后，其本身对 GV 的 use 仍挂在 user 列表里。这些 ConstantExpr 无
            // 任何实际使用者，可安全清除。
            GV->removeDeadConstantUsers();
            if (GV->use_empty())
                GV->eraseFromParent();
            else
                errs() << "BpfEmutls: WARNING: " << GV->getName()
                       << " still has " << GV->getNumUses()
                       << " uses after rewrite (unsupported form)\n";
        }

        return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }

  private:
    // 解析 @llvm.global.annotations，收集所有标注了 annotate("emutls") 的全局。
    // clang 对 __attribute__((annotate("X"))) 的全局会在 @llvm.global.annotations
    //（appending linkage、section "llvm.metadata"）里追加一条
    // { ptr Value, ptr Str, ptr File, i32 Line, ptr Attr }：取 operand[1]（Str）读出
    // 字符串内容，过滤 == "emutls"，收集 operand[0]（Value）指向的 GlobalVariable。
    void collectEmutlsGlobals(Module &M,
                              SmallVectorImpl<GlobalVariable *> &Out) {
        GlobalVariable *Annot = M.getNamedGlobal("llvm.global.annotations");
        if (!Annot)
            return;
        // initializer 可能是 ConstantArray（多条注解），也可能是 zeroinitializer（空）。
        auto *Arr = dyn_cast<ConstantArray>(Annot->getInitializer());
        if (!Arr)
            return;
        for (unsigned i = 0, e = Arr->getNumOperands(); i != e; ++i) {
            // 每个元素是 ConstantStruct { ptr, ptr, ptr, i32, ptr }。
            auto *Elem = dyn_cast<ConstantStruct>(Arr->getOperand(i));
            if (!Elem || Elem->getNumOperands() < 2)
                continue;
            StringRef Str;
            if (!getConstantStringInfo(Elem->getOperand(1), Str))
                continue;
            if (Str != kEmutlsAnnot)
                continue;
            // operand[0] 是被标注的全局（可能经 bitcast，stripPointerCasts 后取 GV）。
            auto *GV = dyn_cast<GlobalVariable>(
                Elem->getOperand(0)->stripPointerCasts());
            if (GV && !GV->isDeclaration())
                Out.push_back(GV);
        }
    }

    // 检测无法正确处理的使用形态，命中则 report_fatal_error 硬退出（绝不静默生成错
    // 误代码）：
    //
    // (1) 全局初始化器里取 emutls 变量地址，如 `int *gp = &tls_var;`——initializer
    //     是编译期 Constant，不在任何函数里，pass 无处插 __emutls_get_address 调用。
    //
    // (2) 带用户构造函数的 thread_local。本 pass 跑在 PipelineStartEP（-O1 优化前），
    //     此类变量的 IR 一律是 `@var = zeroinitializer` + init 函数里 `call @T::T(&var,..)`
    //     ——构造调用还在，没进 GV initializer。pass 无法把构造迁移成每线程执行（需把
    //     构造抽成 thunk 存进控制块），放行会丢构造且只构造一次。聚合初始化（无构造
    //     函数，如 `Point{1,2}`）的 initializer 直接进 GV，init 函数里只剩 __cxa_atexit
    //     （非平凡析构时），不触发本检测。
    void checkUnsupportedForms(Module &M, ArrayRef<GlobalVariable *> EmutlsGlobals) {
        DenseSet<GlobalVariable *> EmutlsSet(EmutlsGlobals.begin(),
                                             EmutlsGlobals.end());

        // (1) 全局初始化器里 &tls_var：遍历所有 GV（排除 pass 合成的控制块/模板与
        //     annotations metadata），检查 initializer 是否引用了 emutls 全局。
        for (GlobalVariable &GV : M.globals()) {
            if (GV.isDeclaration())
                continue;
            StringRef Name = GV.getName();
            if (Name.starts_with("__emutls_v.") || Name.starts_with("__emutls_t."))
                continue; // pass 自己合成的控制块/模板，合法引用
            if (Name == "llvm.global.annotations")
                continue; // annotation metadata 本身
            if (!GV.hasInitializer())
                continue;
            if (GlobalVariable *Ref = findEmutlsGlobalIn(GV.getInitializer(), EmutlsSet)) {
                report_fatal_error(
                    "BpfEmutls: taking address of thread_local var '" +
                    Ref->getName() + "' in the initializer of global '" +
                    GV.getName() + "' is not supported: there is no function "
                    "context to insert __emutls_get_address. Use a function-"
                    "local pointer instead (e.g. compute &var inside a "
                    "function).", false);
            }
        }

        // (2) init 函数（__cxx_global_var_init、_GLOBAL__sub_I_*）里的构造逻辑。构造
        //     只出现在这里；init 函数中对 emutls 全局唯一的合法引用是 __cxa_atexit 的
        //     arg1（dtor 注册，由 collectDtors 处理），其余都是构造逻辑。
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
            StringRef FName = F.getName();
            if (!FName.starts_with("__cxx_global_var_init") &&
                !FName.starts_with("_GLOBAL__sub_I"))
                continue;
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    // __cxa_atexit：arg1 合法，只检查其余 args（防御性）。
                    if (auto *Call = dyn_cast<CallInst>(&I)) {
                        Function *Callee = Call->getCalledFunction();
                        if (Callee && Callee->getName() == "__cxa_atexit" &&
                            Call->arg_size() >= 2) {
                            for (unsigned a = 0; a < Call->arg_size(); ++a) {
                                if (a == 1) continue; // arg1 合法
                                auto *ArgC = dyn_cast<Constant>(Call->getArgOperand(a));
                                if (!ArgC) continue;
                                if (GlobalVariable *Ref =
                                        findEmutlsGlobalIn(ArgC, EmutlsSet))
                                    report_fatal_error(
                                        "BpfEmutls: thread_local var '" +
                                        Ref->getName() + "' has a non-foldable "
                                        "constructor (runtime logic in " +
                                        FName + "); only aggregate "
                                        "initialization (no user constructor) "
                                        "is supported. The constructor call "
                                        "would run once at process startup "
                                        "instead of per-thread.", false);
                            }
                            continue;
                        }
                    }
                    // 其余指令：init 函数里任何对 emutls 全局的引用都是构造逻辑。
                    for (Value *Op : I.operands()) {
                        auto *OpC = dyn_cast<Constant>(Op);
                        if (!OpC) continue;
                        if (GlobalVariable *Ref = findEmutlsGlobalIn(OpC, EmutlsSet))
                            report_fatal_error(
                                "BpfEmutls: thread_local var '" + Ref->getName() +
                                "' has a non-foldable constructor (runtime logic "
                                "in " + FName + "); only aggregate initialization "
                                "(no user constructor) is supported.", false);
                    }
                }
            }
        }
    }

    // 在一个 Constant（可能是 ConstantExpr gep/bitcast 嵌套、ConstantStruct、
    // ConstantArray 等）里递归查找是否引用了某个 emutls 全局。用于检测全局初始化器
    // 里的 &tls_var。返回命中的 emutls 全局，否则 nullptr。
    static GlobalVariable *findEmutlsGlobalIn(const Constant *C,
                                              const DenseSet<GlobalVariable *> &S) {
        if (!C) return nullptr;
        const Constant *Stripped = cast<Constant>(C->stripPointerCasts());
        if (auto *GV = dyn_cast<GlobalVariable>(Stripped))
            return S.count(GV) ? const_cast<GlobalVariable *>(GV) : nullptr;
        for (const Use &U : Stripped->operands()) {
            auto *OpC = dyn_cast<Constant>(U.get());
            if (!OpC) continue;
            if (GlobalVariable *GV = findEmutlsGlobalIn(OpC, S))
                return GV;
        }
        return nullptr;
    }

    // 把一个 emutls 全局在指令 I 处的使用替换成 __emutls_get_address 调用返回的
    // 普通 ptr。返回插入的指针 Value（addrspace 0）。
    Value *materializeAddress(Instruction *I, GlobalVariable *Ctrl,
                              FunctionCallee GetAddr) {
        IRBuilder<> B(I);
        // __emutls_get_address(ptr ctrl) -> ptr，直接传控制块指针、直接返回。
        return B.CreateCall(GetAddr, {Ctrl});
    }

    // 从 init 函数里识别 clang 为非平凡析构 thread_local 生成的
    // `call @__cxa_atexit(dtor, &var, dso)`：把 dtor 回填进 var 对应的控制块，并删除该
    // call。识别条件是被调函数名为 __cxa_atexit，且 arg1（对象地址）经 stripPointerCasts
    // 后是某个 emutls 全局。arg0=dtor 经 bitcast 到 ptr 存入控制块；arg2（dso）不提取
    //——BPF 无 dlopen/dlclose，运行时不使用。
    void collectDtors(Module &M,
                      const DenseMap<GlobalVariable *, GlobalVariable *> &CtrlOf) {
        Type *PtrTy = PointerType::get(M.getContext(), 0);
        SmallVector<CallInst *, 8> ToErase;
        for (Function &F : M) {
            if (F.isDeclaration())
                continue;
            for (BasicBlock &BB : F) {
                for (Instruction &I : BB) {
                    auto *Call = dyn_cast<CallInst>(&I);
                    if (!Call) continue;
                    Function *Callee = Call->getCalledFunction();
                    if (!Callee || Callee->getName() != "__cxa_atexit") continue;
                    if (Call->arg_size() < 3) continue;

                    // arg1 是要析构的对象地址。clang 对 thread_local 生成时，此刻它
                    // 仍是原始 emutls 全局（或其 bitcast）。
                    Value *ObjArg = Call->getArgOperand(1)->stripPointerCasts();
                    auto *GV = dyn_cast<GlobalVariable>(ObjArg);
                    if (!GV || !CtrlOf.count(GV)) continue;

                    // 命中：提取 dtor(arg0) 回填控制块（dso/arg2 不需要，见上）。
                    Constant *Dtor = cast<Constant>(Call->getArgOperand(0));
                    if (Dtor->getType() != PtrTy)
                        Dtor = ConstantExpr::getBitCast(Dtor, PtrTy);
                    setControlDtor(CtrlOf.at(GV), Dtor);
                    ToErase.push_back(Call);
                }
            }
        }
        for (CallInst *Call : ToErase) {
            // arg1 可能是 emutls 全局经 bitcast 的 ConstantExpr，仍挂在 GV
            // 的 user 列表上；先撤掉 Call 对它的引用，再 erase，避免后续 use 检查报警。
            Call->eraseFromParent();
        }
    }

    // 判断一个 Value（含 ConstantExpr）是否涉及某个 emutls 全局。
    // ConstantExpr 如 `gep(@arr, ...)` 内部会引用 GV，需递归检查。
    static GlobalVariable *findEmutlsGlobal(const Value *V,
                              const DenseMap<GlobalVariable *, GlobalVariable *> &CtrlOf) {
        V = V->stripPointerCasts();
        if (auto *GV = const_cast<GlobalVariable *>(dyn_cast<GlobalVariable>(V)))
            return CtrlOf.count(GV) ? GV : nullptr;
        // ConstantExpr：递归 operand 查找。
        if (auto *CE = dyn_cast<ConstantExpr>(V)) {
            for (const Use &U : CE->operands()) {
                if (auto *GV = findEmutlsGlobal(U.get(), CtrlOf))
                    return GV;
            }
        }
        return nullptr;
    }

    bool rewriteFunction(Function &F,
                         const DenseMap<GlobalVariable *, GlobalVariable *> &CtrlOf,
                         FunctionCallee GetAddr) {
        bool Changed = false;

        // 第一阶段：把所有以 ConstantExpr 形式引用 emutls 全局的 operand 展开成
        // 真实指令（CL在被使用处插一条 Instruction）。这样后续阶段只需处理指令形式。
        // clang -O0/-O1 对 `arr[i]`、`&s->field` 等会生成 ConstantExpr 形式的 GEP/
        // bitcast 嵌进 load/store 的指针 operand，无法直接替换。
        SmallVector<std::pair<Use *, GlobalVariable *>, 32> CEWorklist;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                for (Use &U : I.operands()) {
                    if (!isa<ConstantExpr>(U.get())) continue;
                    if (auto *GV = findEmutlsGlobal(U.get(), CtrlOf))
                        CEWorklist.push_back({&U, GV});
                }
            }
        }
        for (auto &[U, GV] : CEWorklist) {
            auto *CE = cast<ConstantExpr>(U->get());
            auto *I = cast<Instruction>(U->getUser());
            // 把 ConstantExpr 在 I 之前展开成 Instruction。
            Instruction *Expanded = CE->getAsInstruction();
#if LLVM_VERSION_MAJOR >= 21
            Expanded->insertBefore(I->getIterator());
#else
            Expanded->insertBefore(I);
#endif
            U->set(Expanded);
            Changed = true;
        }

        // 第二阶段：处理所有"以 emutls 全局为源指针"的 GetElementPtrInst（含上一
        // 阶段从 ConstantExpr 展开出来的）。GEP 的 base 指向 emutls 全局，必须把 base
        // 换成 __emutls_get_address 返回的每线程副本指针——整体重建一个 GEP 再 RAUW，
        // 不能只换 operand（原 GEP 绑定的是全局地址，不是副本地址）。
        SmallVector<GetElementPtrInst *, 16> GEPs;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                auto *GEP = dyn_cast<GetElementPtrInst>(&I);
                if (!GEP) continue;
                auto *GV = findEmutlsGlobal(GEP->getPointerOperand(), CtrlOf);
                if (GV)
                    GEPs.push_back(GEP);
            }
        }
        for (GetElementPtrInst *GEP : GEPs) {
            auto *GV = findEmutlsGlobal(GEP->getPointerOperand(), CtrlOf);
            GlobalVariable *Ctrl = CtrlOf.at(GV);
            // GEP 的 pointer operand 可能是 GV 本身，也可能是 stripPointerCasts 后
            // 是 GV 的 bitcast。先在 GEP 处 materialize 拿到普通 ptr 基地址。
            Value *Base = materializeAddress(GEP, Ctrl, GetAddr);
            IRBuilder<> B(GEP);
            // 若原指针经 bitcast，重建 bitcast(Base)。
            Value *OrigPtr = GEP->getPointerOperand();
            if (OrigPtr != GV && OrigPtr->stripPointerCasts() == GV) {
                if (auto *BC = dyn_cast<BitCastOperator>(OrigPtr))
                    Base = B.CreateBitCast(Base, BC->getType());
            }
            SmallVector<Value *, 4> Idxs(GEP->indices().begin(), GEP->indices().end());
            Value *NewGEP = B.CreateGEP(GEP->getSourceElementType(), Base, Idxs,
                                         GEP->getName() + ".emutls", GEP->isInBounds());
            GEP->replaceAllUsesWith(NewGEP);
            GEP->eraseFromParent();
            Changed = true;
        }

        // 第三阶段：剩余所有直接以 emutls 全局（或其 bitcast 包裹）为 operand 的
        // 指令（load/store/icmp 等）。
        SmallVector<std::pair<Instruction *, GlobalVariable *>, 16> Worklist;
        for (BasicBlock &BB : F) {
            for (Instruction &I : BB) {
                for (Value *Op : I.operands()) {
                    if (auto *GV = findEmutlsGlobal(Op, CtrlOf))
                        Worklist.push_back({&I, GV});
                }
            }
        }
        for (auto &[I, GV] : Worklist) {
            GlobalVariable *Ctrl = CtrlOf.at(GV);
            Value *Ptr = materializeAddress(I, Ctrl, GetAddr);
            for (Use &U : I->operands()) {
                Value *V = U.get();
                if (V == GV) {
                    U.set(Ptr);
                } else if (V->stripPointerCasts() == GV) {
                    IRBuilder<> B(I);
                    if (auto *BC = dyn_cast<BitCastOperator>(V))
                        U.set(B.CreateBitCast(Ptr, BC->getType()));
                    else
                        U.set(Ptr);
                }
            }
            Changed = true;
        }
        return Changed;
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BpfEmutls", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                // 必须早跑：在常量折叠/GlobalOpt 把 emutls 全局当成可折叠常量之前
                //（它们语义上是每线程副本，绝不能被折叠进用户 initializer）。PipelineStartEP
                // 全档位（-O0/-O1+ 都跑）。
                auto addPass = [](ModulePassManager &MPM) {
                    MPM.addPass(BpfEmutlsPass());
                };
                PB.registerPipelineStartEPCallback(
                    [addPass](ModulePassManager &MPM, OptimizationLevel) {
                        addPass(MPM);
                    });
            }};
}
