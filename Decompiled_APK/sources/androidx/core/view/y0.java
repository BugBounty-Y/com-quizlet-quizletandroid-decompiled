package androidx.core.view;

import android.view.WindowInsets;

/* loaded from: classes.dex */
public final class y0 extends x0 {
    public static final D0 s = D0.h(null, WindowInsets.CONSUMED);

    public y0(D0 d0, WindowInsets windowInsets) {
        super(d0, windowInsets);
    }

    @Override // androidx.core.view.x0, androidx.core.view.t0, androidx.core.view.z0
    public androidx.core.graphics.e g(int i) {
        return androidx.core.graphics.e.c(this.c.getInsets(C0.a(i)));
    }

    @Override // androidx.core.view.x0, androidx.core.view.t0, androidx.core.view.z0
    public androidx.core.graphics.e h(int i) {
        return androidx.core.graphics.e.c(this.c.getInsetsIgnoringVisibility(C0.a(i)));
    }

    @Override // androidx.core.view.x0, androidx.core.view.t0, androidx.core.view.z0
    public boolean q(int i) {
        return this.c.isVisible(C0.a(i));
    }

    public y0(D0 d0, y0 y0Var) {
        super(d0, y0Var);
    }
}
