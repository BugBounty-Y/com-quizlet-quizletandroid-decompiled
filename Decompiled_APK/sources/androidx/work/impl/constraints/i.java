package androidx.work.impl.constraints;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class i {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;

    public i(boolean z, boolean z2, boolean z3, boolean z4) {
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b == iVar.b && this.c == iVar.c && this.d == iVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NetworkState(isConnected=");
        sb.append(this.a);
        sb.append(", isValidated=");
        sb.append(this.b);
        sb.append(", isMetered=");
        sb.append(this.c);
        sb.append(", isNotRoaming=");
        return android.support.v4.media.session.a.u(sb, this.d, ')');
    }
}
