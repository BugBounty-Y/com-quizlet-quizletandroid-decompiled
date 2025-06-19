package androidx.core.graphics;

import android.graphics.Insets;

/* loaded from: classes.dex */
public final class e {
    public static final e e = new e(0, 0, 0, 0);
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public e(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public static e a(e eVar, e eVar2) {
        return b(Math.max(eVar.a, eVar2.a), Math.max(eVar.b, eVar2.b), Math.max(eVar.c, eVar2.c), Math.max(eVar.d, eVar2.d));
    }

    public static e b(int i, int i2, int i3, int i4) {
        return (i == 0 && i2 == 0 && i3 == 0 && i4 == 0) ? e : new e(i, i2, i3, i4);
    }

    public static e c(Insets insets) {
        return b(insets.left, insets.top, insets.right, insets.bottom);
    }

    public final Insets d() {
        return c.c(this.a, this.b, this.c, this.d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || e.class != obj.getClass()) {
            return false;
        }
        e eVar = (e) obj;
        return this.d == eVar.d && this.a == eVar.a && this.c == eVar.c && this.b == eVar.b;
    }

    public final int hashCode() {
        return (((((this.a * 31) + this.b) * 31) + this.c) * 31) + this.d;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Insets{left=");
        sb.append(this.a);
        sb.append(", top=");
        sb.append(this.b);
        sb.append(", right=");
        sb.append(this.c);
        sb.append(", bottom=");
        return android.support.v4.media.session.a.q(sb, this.d, '}');
    }
}
