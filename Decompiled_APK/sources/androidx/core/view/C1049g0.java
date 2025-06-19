package androidx.core.view;

import android.animation.ValueAnimator;
import android.os.Build;
import android.view.View;
import android.view.animation.PathInterpolator;
import java.util.Collections;

/* renamed from: androidx.core.view.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1049g0 implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ m0 a;
    public final /* synthetic */ D0 b;
    public final /* synthetic */ D0 c;
    public final /* synthetic */ int d;
    public final /* synthetic */ View e;

    public C1049g0(m0 m0Var, D0 d0, D0 d02, int i, View view) {
        this.a = m0Var;
        this.b = d0;
        this.c = d02;
        this.d = i;
        this.e = view;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        float f;
        int i;
        float animatedFraction = valueAnimator.getAnimatedFraction();
        m0 m0Var = this.a;
        m0Var.a.d(animatedFraction);
        float fB = m0Var.a.b();
        PathInterpolator pathInterpolator = i0.e;
        int i2 = Build.VERSION.SDK_INT;
        D0 d0 = this.b;
        s0 r0Var = i2 >= 34 ? new r0(d0) : i2 >= 30 ? new q0(d0) : i2 >= 29 ? new p0(d0) : new n0(d0);
        int i3 = 1;
        while (i3 <= 512) {
            int i4 = this.d & i3;
            z0 z0Var = d0.a;
            if (i4 == 0) {
                r0Var.c(i3, z0Var.g(i3));
                f = fB;
                i = 1;
            } else {
                androidx.core.graphics.e eVarG = z0Var.g(i3);
                androidx.core.graphics.e eVarG2 = this.c.a.g(i3);
                float f2 = 1.0f - fB;
                f = fB;
                i = 1;
                r0Var.c(i3, D0.e(eVarG, (int) (((eVarG.a - eVarG2.a) * f2) + 0.5d), (int) (((eVarG.b - eVarG2.b) * f2) + 0.5d), (int) (((eVarG.c - eVarG2.c) * f2) + 0.5d), (int) (((eVarG.d - eVarG2.d) * f2) + 0.5d)));
            }
            i3 <<= i;
            fB = f;
        }
        i0.g(this.e, r0Var.b(), Collections.singletonList(m0Var));
    }
}
