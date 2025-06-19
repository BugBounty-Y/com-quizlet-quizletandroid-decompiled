package androidx.core.view;

import android.view.View;
import android.view.WindowInsets;

/* loaded from: classes.dex */
public class x0 extends w0 {
    public static final D0 r = D0.h(null, WindowInsets.CONSUMED);

    public x0(D0 d0, WindowInsets windowInsets) {
        super(d0, windowInsets);
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public final void d(View view) {
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public androidx.core.graphics.e g(int i) {
        return androidx.core.graphics.e.c(this.c.getInsets(B0.a(i)));
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public androidx.core.graphics.e h(int i) {
        return androidx.core.graphics.e.c(this.c.getInsetsIgnoringVisibility(B0.a(i)));
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public boolean q(int i) {
        return this.c.isVisible(B0.a(i));
    }

    public x0(D0 d0, x0 x0Var) {
        super(d0, x0Var);
    }
}
