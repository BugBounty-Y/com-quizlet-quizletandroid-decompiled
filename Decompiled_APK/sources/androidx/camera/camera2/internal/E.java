package androidx.camera.camera2.internal;

import androidx.camera.core.C0152d;

/* loaded from: classes.dex */
public final class E extends androidx.lifecycle.X {
    public androidx.lifecycle.Y n;
    public final C0152d o;

    public E(C0152d c0152d) {
        super(0);
        this.o = c0152d;
    }

    @Override // androidx.lifecycle.T
    public final Object d() {
        androidx.lifecycle.Y y = this.n;
        return y == null ? this.o : y.d();
    }

    @Override // androidx.lifecycle.X
    public final void m(androidx.lifecycle.T t, androidx.lifecycle.Z z) {
        throw new UnsupportedOperationException();
    }

    public final void n(androidx.lifecycle.Y y) {
        androidx.lifecycle.W w;
        androidx.lifecycle.Y y2 = this.n;
        if (y2 != null && (w = (androidx.lifecycle.W) ((androidx.arch.core.internal.f) this.m).b(y2)) != null) {
            w.a.k(w);
        }
        this.n = y;
        super.m(y, new D(this, 0));
    }
}
