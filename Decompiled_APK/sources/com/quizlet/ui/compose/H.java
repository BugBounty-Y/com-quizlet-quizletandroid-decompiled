package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.gestures.AbstractC0349s0;
import androidx.compose.foundation.gestures.C0321e;
import com.google.android.gms.internal.mlkit_vision_barcode.B5;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ float m;
    public final /* synthetic */ kotlinx.coroutines.C n;
    public final /* synthetic */ float o;
    public final /* synthetic */ Function0 p;
    public final /* synthetic */ Function0 q;
    public final /* synthetic */ C0238e r;
    public final /* synthetic */ Function1 s;
    public final /* synthetic */ Function1 t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(C0238e c0238e, float f, kotlinx.coroutines.C c, float f2, Function0 function0, Function0 function02, C0238e c0238e2, Function1 function1, Function1 function12, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0238e;
        this.m = f;
        this.n = c;
        this.o = f2;
        this.p = function0;
        this.q = function02;
        this.r = c0238e2;
        this.s = function1;
        this.t = function12;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        H h = new H(this.l, this.m, this.n, this.o, this.p, this.q, this.r, this.s, this.t, hVar);
        h.k = obj;
        return h;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i = 0;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i2 = this.j;
        if (i2 == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            final kotlinx.coroutines.C c = this.n;
            final Function1 function1 = this.s;
            final Function1 function12 = this.t;
            final C0238e c0238e = this.l;
            final float f = this.m;
            final float f2 = this.o;
            final Function0 function0 = this.p;
            final Function0 function02 = this.q;
            final C0238e c0238e2 = this.r;
            Function0 function03 = new Function0() { // from class: com.quizlet.ui.compose.D
                @Override // kotlin.jvm.functions.Function0
                public final Object invoke() {
                    C0238e c0238e3 = c0238e;
                    float fAbs = Math.abs(((Number) c0238e3.d()).floatValue());
                    float f3 = f;
                    kotlinx.coroutines.C c2 = c;
                    C0238e c0238e4 = c0238e2;
                    Function1 function13 = function1;
                    Function1 function14 = function12;
                    if (fAbs > f3) {
                        kotlinx.coroutines.E.A(c2, null, null, new E(c0238e3, f2, function0, function02, c0238e4, function13, function14, null), 3);
                    } else {
                        B5.c(c2, c0238e3, c0238e4, function13, function14);
                    }
                    return Unit.a;
                }
            };
            C0238e c0238e3 = this.l;
            C0238e c0238e4 = this.r;
            Function1 function13 = this.s;
            Function1 function14 = this.t;
            F f3 = new F(c, c0238e3, c0238e4, function13, function14);
            com.quizlet.search.composables.p pVar = new com.quizlet.search.composables.p(c, c0238e3, function14, function13, c0238e4, this.m);
            this.j = 1;
            float f4 = androidx.compose.foundation.gestures.H.a;
            Object objD = AbstractC0349s0.d(b, new androidx.compose.foundation.gestures.F(androidx.compose.foundation.gestures.E.a, new kotlin.jvm.internal.I(), null, new androidx.compose.foundation.gestures.C(i, C0321e.c), pVar, f3, new androidx.compose.foundation.gestures.D(0, function03), null), this);
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
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
