package androidx.compose.foundation.text;

import androidx.compose.animation.C0281h;
import androidx.compose.foundation.gestures.AbstractC0349s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0508m0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B k;
    public final /* synthetic */ u0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0508m0(androidx.compose.ui.input.pointer.B b, u0 u0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = b;
        this.l = u0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0508m0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0508m0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            u0 u0Var = this.l;
            C0512o0 c0512o0 = new C0512o0(u0Var, 0);
            C0514p0 c0514p0 = new C0514p0(u0Var, 0);
            C0514p0 c0514p02 = new C0514p0(u0Var, 1);
            C0281h c0281h = new C0281h(u0Var, 10);
            float f = androidx.compose.foundation.gestures.H.a;
            Object objD = AbstractC0349s0.d(this.k, new androidx.compose.foundation.gestures.F(androidx.compose.foundation.gestures.E.a, new kotlin.jvm.internal.I(), null, new androidx.compose.foundation.gestures.C(0, c0512o0), c0281h, c0514p02, new androidx.compose.foundation.gestures.D(0, c0514p0), null), this);
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD != obj2) {
                objD = Unit.a;
            }
            if (objD == obj2) {
                return obj2;
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
