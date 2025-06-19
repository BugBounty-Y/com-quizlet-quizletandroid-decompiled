package androidx.work;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5038w;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: androidx.work.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1444s implements androidx.concurrent.futures.j, io.reactivex.rxjava3.core.r {
    public final /* synthetic */ CoroutineContext a;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i b;

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ C1444s(CoroutineContext coroutineContext, Function2 function2, int i) {
        switch (i) {
            case 1:
                this.a = coroutineContext;
                this.b = (kotlin.coroutines.jvm.internal.i) function2;
                break;
            default:
                kotlinx.coroutines.D d = kotlinx.coroutines.D.a;
                this.a = coroutineContext;
                this.b = (kotlin.coroutines.jvm.internal.i) function2;
                break;
        }
    }

    /* JADX WARN: Type inference failed for: r2v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i completer) {
        Intrinsics.checkNotNullParameter(completer, "completer");
        C5023i0 c5023i0 = C5023i0.a;
        CoroutineContext coroutineContext = this.a;
        completer.a(new androidx.compose.ui.text.input.C((InterfaceC5025j0) coroutineContext.get(c5023i0), 8), EnumC1440n.a);
        return kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(coroutineContext), null, kotlinx.coroutines.D.a, new C1445t(this.b, completer, null), 1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v4, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // io.reactivex.rxjava3.core.r
    public void j(io.reactivex.rxjava3.internal.operators.single.c cVar) {
        CoroutineContext coroutineContextA = AbstractC5038w.a(kotlin.coroutines.n.a, this.a, true);
        kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
        if (coroutineContextA != eVar && coroutineContextA.get(kotlin.coroutines.j.a1) == null) {
            coroutineContextA = coroutineContextA.plus(eVar);
        }
        kotlinx.coroutines.rx3.i iVar = new kotlinx.coroutines.rx3.i(coroutineContextA, cVar);
        io.reactivex.rxjava3.internal.disposables.a.d(cVar, new io.reactivex.rxjava3.disposables.d(new kotlinx.coroutines.rx3.e(iVar), 1));
        iVar.m0(kotlinx.coroutines.D.a, iVar, this.b);
    }
}
