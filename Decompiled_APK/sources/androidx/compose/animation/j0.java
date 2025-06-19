package androidx.compose.animation;

import androidx.compose.animation.core.C0238e;

/* loaded from: classes.dex */
public final class j0 {
    public final C0238e a;
    public long b;

    public j0(C0238e c0238e, long j) {
        this.a = c0238e;
        this.b = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j0)) {
            return false;
        }
        j0 j0Var = (j0) obj;
        return this.a.equals(j0Var.a) && androidx.compose.ui.unit.j.a(this.b, j0Var.b);
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AnimData(anim=" + this.a + ", startSize=" + ((Object) androidx.compose.ui.unit.j.b(this.b)) + ')';
    }
}
