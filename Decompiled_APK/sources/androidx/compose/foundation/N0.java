package androidx.compose.foundation;

import androidx.compose.foundation.gestures.C0350t;
import androidx.compose.runtime.C0776c;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N0 implements androidx.compose.foundation.gestures.E0 {
    public static final com.quizlet.data.repository.explanations.myexplanations.a i;
    public final androidx.compose.runtime.H0 a;
    public float e;
    public final androidx.compose.runtime.H0 b = C0776c.w(0);
    public final androidx.compose.foundation.interaction.m c = new androidx.compose.foundation.interaction.m();
    public final androidx.compose.runtime.H0 d = C0776c.w(SubsamplingScaleImageView.TILE_SIZE_AUTO);
    public final C0350t f = new C0350t(new androidx.camera.lifecycle.f(this, 9));
    public final androidx.compose.runtime.E g = C0776c.q(new M0(this, 1));
    public final androidx.compose.runtime.E h = C0776c.q(new M0(this, 0));

    static {
        L0 l0 = L0.a;
        C0476t c0476t = C0476t.f;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        i = new com.quizlet.data.repository.explanations.myexplanations.a(l0, false, c0476t, 3);
    }

    public N0(int i2) {
        this.a = C0776c.w(i2);
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return this.f.a();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean b() {
        return ((Boolean) this.h.getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final Object c(u0 u0Var, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        Object objC = this.f.c(u0Var, function2, cVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean d() {
        return ((Boolean) this.g.getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return this.f.e(f);
    }

    public final int f() {
        return this.d.i();
    }

    public final int g() {
        return this.a.i();
    }
}
