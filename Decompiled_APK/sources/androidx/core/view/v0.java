package androidx.core.view;

import android.view.DisplayCutout;
import android.view.WindowInsets;
import java.util.Objects;

/* loaded from: classes.dex */
public class v0 extends u0 {
    public v0(D0 d0, WindowInsets windowInsets) {
        super(d0, windowInsets);
    }

    @Override // androidx.core.view.z0
    public D0 a() {
        return D0.h(null, this.c.consumeDisplayCutout());
    }

    @Override // androidx.core.view.t0, androidx.core.view.z0
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v0)) {
            return false;
        }
        v0 v0Var = (v0) obj;
        return Objects.equals(this.c, v0Var.c) && Objects.equals(this.g, v0Var.g) && t0.C(this.h, v0Var.h);
    }

    @Override // androidx.core.view.z0
    public C1054k f() {
        DisplayCutout displayCutout = this.c.getDisplayCutout();
        if (displayCutout == null) {
            return null;
        }
        return new C1054k(displayCutout);
    }

    @Override // androidx.core.view.z0
    public int hashCode() {
        return this.c.hashCode();
    }

    public v0(D0 d0, v0 v0Var) {
        super(d0, v0Var);
    }
}
