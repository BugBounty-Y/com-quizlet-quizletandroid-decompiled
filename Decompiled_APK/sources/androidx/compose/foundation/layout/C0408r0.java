package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.r0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0408r0 {
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public C0408r0(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0408r0)) {
            return false;
        }
        C0408r0 c0408r0 = (C0408r0) obj;
        return this.a == c0408r0.a && this.b == c0408r0.b && this.c == c0408r0.c && this.d == c0408r0.d;
    }

    public final int hashCode() {
        return (((((this.a * 31) + this.b) * 31) + this.c) * 31) + this.d;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("InsetsValues(left=");
        sb.append(this.a);
        sb.append(", top=");
        sb.append(this.b);
        sb.append(", right=");
        sb.append(this.c);
        sb.append(", bottom=");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
