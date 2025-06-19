package androidx.core.view;

import android.view.WindowInsets;

/* loaded from: classes.dex */
public class u0 extends t0 {
    public androidx.core.graphics.e n;

    public u0(D0 d0, WindowInsets windowInsets) {
        super(d0, windowInsets);
        this.n = null;
    }

    @Override // androidx.core.view.z0
    public D0 b() {
        return D0.h(null, this.c.consumeStableInsets());
    }

    @Override // androidx.core.view.z0
    public D0 c() {
        return D0.h(null, this.c.consumeSystemWindowInsets());
    }

    @Override // androidx.core.view.z0
    public final androidx.core.graphics.e j() {
        if (this.n == null) {
            WindowInsets windowInsets = this.c;
            this.n = androidx.core.graphics.e.b(windowInsets.getStableInsetLeft(), windowInsets.getStableInsetTop(), windowInsets.getStableInsetRight(), windowInsets.getStableInsetBottom());
        }
        return this.n;
    }

    @Override // androidx.core.view.z0
    public boolean o() {
        return this.c.isConsumed();
    }

    @Override // androidx.core.view.z0
    public void u(androidx.core.graphics.e eVar) {
        this.n = eVar;
    }

    public u0(D0 d0, u0 u0Var) {
        super(d0, u0Var);
        this.n = null;
        this.n = u0Var.n;
    }
}
