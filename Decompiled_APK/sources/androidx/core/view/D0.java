package androidx.core.view;

import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import java.util.Objects;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class D0 {
    public static final D0 b;
    public final z0 a;

    static {
        int i = Build.VERSION.SDK_INT;
        if (i >= 34) {
            b = y0.s;
        } else if (i >= 30) {
            b = x0.r;
        } else {
            b = z0.b;
        }
    }

    public D0(WindowInsets windowInsets) {
        int i = Build.VERSION.SDK_INT;
        if (i >= 34) {
            this.a = new y0(this, windowInsets);
            return;
        }
        if (i >= 30) {
            this.a = new x0(this, windowInsets);
            return;
        }
        if (i >= 29) {
            this.a = new w0(this, windowInsets);
        } else if (i >= 28) {
            this.a = new v0(this, windowInsets);
        } else {
            this.a = new u0(this, windowInsets);
        }
    }

    public static androidx.core.graphics.e e(androidx.core.graphics.e eVar, int i, int i2, int i3, int i4) {
        int iMax = Math.max(0, eVar.a - i);
        int iMax2 = Math.max(0, eVar.b - i2);
        int iMax3 = Math.max(0, eVar.c - i3);
        int iMax4 = Math.max(0, eVar.d - i4);
        return (iMax == i && iMax2 == i2 && iMax3 == i3 && iMax4 == i4) ? eVar : androidx.core.graphics.e.b(iMax, iMax2, iMax3, iMax4);
    }

    public static D0 h(View view, WindowInsets windowInsets) {
        windowInsets.getClass();
        D0 d0 = new D0(windowInsets);
        if (view != null && view.isAttachedToWindow()) {
            WeakHashMap weakHashMap = V.a;
            D0 d0A = M.a(view);
            z0 z0Var = d0.a;
            z0Var.t(d0A);
            z0Var.d(view.getRootView());
            z0Var.v(view.getWindowSystemUiVisibility());
        }
        return d0;
    }

    public final int a() {
        return this.a.l().d;
    }

    public final int b() {
        return this.a.l().a;
    }

    public final int c() {
        return this.a.l().c;
    }

    public final int d() {
        return this.a.l().b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D0)) {
            return false;
        }
        return Objects.equals(this.a, ((D0) obj).a);
    }

    public final D0 f(int i, int i2, int i3, int i4) {
        int i5 = Build.VERSION.SDK_INT;
        s0 r0Var = i5 >= 34 ? new r0(this) : i5 >= 30 ? new q0(this) : i5 >= 29 ? new p0(this) : new n0(this);
        r0Var.g(androidx.core.graphics.e.b(i, i2, i3, i4));
        return r0Var.b();
    }

    public final WindowInsets g() {
        z0 z0Var = this.a;
        if (z0Var instanceof t0) {
            return ((t0) z0Var).c;
        }
        return null;
    }

    public final int hashCode() {
        z0 z0Var = this.a;
        if (z0Var == null) {
            return 0;
        }
        return z0Var.hashCode();
    }

    public D0(D0 d0) {
        if (d0 != null) {
            z0 z0Var = d0.a;
            int i = Build.VERSION.SDK_INT;
            if (i >= 34 && (z0Var instanceof y0)) {
                this.a = new y0(this, (y0) z0Var);
            } else if (i >= 30 && (z0Var instanceof x0)) {
                this.a = new x0(this, (x0) z0Var);
            } else if (i >= 29 && (z0Var instanceof w0)) {
                this.a = new w0(this, (w0) z0Var);
            } else if (i >= 28 && (z0Var instanceof v0)) {
                this.a = new v0(this, (v0) z0Var);
            } else if (z0Var instanceof u0) {
                this.a = new u0(this, (u0) z0Var);
            } else if (z0Var instanceof t0) {
                this.a = new t0(this, (t0) z0Var);
            } else {
                this.a = new z0(this);
            }
            z0Var.e(this);
            return;
        }
        this.a = new z0(this);
    }
}
