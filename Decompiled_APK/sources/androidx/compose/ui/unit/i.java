package androidx.compose.ui.unit;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class i {
    public static final i e = new i(0, 0, 0, 0);
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public i(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public final int a() {
        return this.d - this.b;
    }

    public final int b() {
        return this.c - this.a;
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
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IntRect.fromLTRB(");
        sb.append(this.a);
        sb.append(", ");
        sb.append(this.b);
        sb.append(", ");
        sb.append(this.c);
        sb.append(", ");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
