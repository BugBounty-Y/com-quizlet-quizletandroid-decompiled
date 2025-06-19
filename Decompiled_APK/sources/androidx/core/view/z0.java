package androidx.core.view;

import android.os.Build;
import android.view.View;
import java.util.Objects;

/* loaded from: classes.dex */
public class z0 {
    public static final D0 b;
    public final D0 a;

    static {
        int i = Build.VERSION.SDK_INT;
        b = (i >= 34 ? new r0() : i >= 30 ? new q0() : i >= 29 ? new p0() : new n0()).b().a.a().a.b().a.c();
    }

    public z0(D0 d0) {
        this.a = d0;
    }

    public D0 a() {
        return this.a;
    }

    public D0 b() {
        return this.a;
    }

    public D0 c() {
        return this.a;
    }

    public void d(View view) {
    }

    public void e(D0 d0) {
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z0)) {
            return false;
        }
        z0 z0Var = (z0) obj;
        return p() == z0Var.p() && o() == z0Var.o() && Objects.equals(l(), z0Var.l()) && Objects.equals(j(), z0Var.j()) && Objects.equals(f(), z0Var.f());
    }

    public C1054k f() {
        return null;
    }

    public androidx.core.graphics.e g(int i) {
        return androidx.core.graphics.e.e;
    }

    public androidx.core.graphics.e h(int i) {
        if ((i & 8) == 0) {
            return androidx.core.graphics.e.e;
        }
        throw new IllegalArgumentException("Unable to query the maximum insets for IME");
    }

    public int hashCode() {
        return Objects.hash(Boolean.valueOf(p()), Boolean.valueOf(o()), l(), j(), f());
    }

    public androidx.core.graphics.e i() {
        return l();
    }

    public androidx.core.graphics.e j() {
        return androidx.core.graphics.e.e;
    }

    public androidx.core.graphics.e k() {
        return l();
    }

    public androidx.core.graphics.e l() {
        return androidx.core.graphics.e.e;
    }

    public androidx.core.graphics.e m() {
        return l();
    }

    public D0 n(int i, int i2, int i3, int i4) {
        return b;
    }

    public boolean o() {
        return false;
    }

    public boolean p() {
        return false;
    }

    public boolean q(int i) {
        return true;
    }

    public void r(androidx.core.graphics.e[] eVarArr) {
    }

    public void s(androidx.core.graphics.e eVar) {
    }

    public void t(D0 d0) {
    }

    public void u(androidx.core.graphics.e eVar) {
    }

    public void v(int i) {
    }
}
