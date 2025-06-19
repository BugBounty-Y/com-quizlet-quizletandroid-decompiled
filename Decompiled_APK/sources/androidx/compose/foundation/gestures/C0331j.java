package androidx.compose.foundation.gestures;

import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: androidx.compose.foundation.gestures.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0331j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0333k l;
    public final /* synthetic */ o1 m;
    public final /* synthetic */ InterfaceC0319d n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0331j(C0333k c0333k, o1 o1Var, InterfaceC0319d interfaceC0319d, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0333k;
        this.m = o1Var;
        this.n = interfaceC0319d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0331j c0331j = new C0331j(this.l, this.m, this.n, hVar);
        c0331j.k = obj;
        return c0331j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0331j) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0333k c0333k = this.l;
        try {
            try {
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5025j0 interfaceC5025j0S = kotlinx.coroutines.E.s(((kotlinx.coroutines.C) this.k).getCoroutineContext());
                    c0333k.w = true;
                    L0 l0 = c0333k.o;
                    androidx.compose.foundation.u0 u0Var = androidx.compose.foundation.u0.a;
                    C0329i c0329i = new C0329i(this.m, c0333k, this.n, interfaceC5025j0S, null);
                    this.j = 1;
                    if (l0.e(u0Var, c0329i, this) == aVar) {
                        return aVar;
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                c0333k.r.n();
                c0333k.w = false;
                c0333k.r.k(null);
                c0333k.u = false;
                return Unit.a;
            } catch (CancellationException e) {
                throw e;
            }
        } catch (Throwable th) {
            c0333k.w = false;
            c0333k.r.k(null);
            c0333k.u = false;
            throw th;
        }
    }
}
