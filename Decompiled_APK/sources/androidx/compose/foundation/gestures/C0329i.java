package androidx.compose.foundation.gestures;

import androidx.compose.foundation.C0473q;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;

/* renamed from: androidx.compose.foundation.gestures.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0329i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ o1 l;
    public final /* synthetic */ C0333k m;
    public final /* synthetic */ InterfaceC0319d n;
    public final /* synthetic */ InterfaceC5025j0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0329i(o1 o1Var, C0333k c0333k, InterfaceC0319d interfaceC0319d, InterfaceC5025j0 interfaceC5025j0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o1Var;
        this.m = c0333k;
        this.n = interfaceC0319d;
        this.o = interfaceC5025j0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0329i c0329i = new C0329i(this.l, this.m, this.n, this.o, hVar);
        c0329i.k = obj;
        return c0329i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0329i) create((I0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            I0 i0 = (I0) this.k;
            InterfaceC0319d interfaceC0319d = this.n;
            C0333k c0333k = this.m;
            float fM0 = C0333k.M0(c0333k, interfaceC0319d);
            o1 o1Var = this.l;
            o1Var.e = fM0;
            androidx.activity.compose.g gVar = new androidx.activity.compose.g(c0333k, this.o, i0, 5);
            C0473q c0473q = new C0473q(c0333k, o1Var, interfaceC0319d, 1);
            this.j = 1;
            if (o1Var.a(gVar, c0473q, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
