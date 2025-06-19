package androidx.core.view;

import android.view.WindowInsets;

/* loaded from: classes.dex */
public class w0 extends v0 {
    public androidx.core.graphics.e o;
    public androidx.core.graphics.e p;
    public androidx.core.graphics.e q;

    public w0(D0 d0, WindowInsets windowInsets) {
        super(d0, windowInsets);
        this.o = null;
        this.p = null;
        this.q = null;
    }

    @Override // androidx.core.view.z0
    public androidx.core.graphics.e i() {
        if (this.p == null) {
            this.p = androidx.core.graphics.e.c(this.c.getMandatorySystemGestureInsets());
        }
        return this.p;
    }

    @Override // androidx.core.view.z0
    public androidx.core.graphics.e k() {
        if (this.o == null) {
            this.o = androidx.core.graphics.e.c(this.c.getSystemGestureInsets());
        }
        return this.o;
    }

    @Override // androidx.core.view.z0
    public androidx.core.graphics.e m() {
        if (this.q == null) {
            this.q = androidx.core.graphics.e.c(this.c.getTappableElementInsets());
        }
        return this.q;
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public D0 n(int i, int i2, int i3, int i4) {
        return D0.h(null, this.c.inset(i, i2, i3, i4));
    }

    @Override // androidx.core.view.u0, androidx.core.view.z0
    public void u(androidx.core.graphics.e eVar) {
    }

    public w0(D0 d0, w0 w0Var) {
        super(d0, w0Var);
        this.o = null;
        this.p = null;
        this.q = null;
    }
}
