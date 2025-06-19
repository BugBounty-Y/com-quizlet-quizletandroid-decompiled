package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0350t k;
    public final /* synthetic */ androidx.compose.foundation.u0 l;
    public final /* synthetic */ Function2 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(C0350t c0350t, androidx.compose.foundation.u0 u0Var, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0350t;
        this.l = u0Var;
        this.m = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0350t c0350t = this.k;
            androidx.compose.foundation.y0 y0Var = c0350t.c;
            C0348s c0348s = c0350t.b;
            C0345q c0345q = new C0345q(c0350t, this.m, null);
            this.j = 1;
            y0Var.getClass();
            if (kotlinx.coroutines.E.m(new androidx.compose.foundation.x0(this.l, y0Var, c0345q, c0348s, null), this) == aVar) {
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
