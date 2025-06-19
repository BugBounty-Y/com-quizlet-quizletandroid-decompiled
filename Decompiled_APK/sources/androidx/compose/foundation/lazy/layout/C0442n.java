package androidx.compose.foundation.lazy.layout;

/* renamed from: androidx.compose.foundation.lazy.layout.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0442n {
    public final int a;
    public final int b;

    public C0442n(int i, int i2) {
        this.a = i;
        this.b = i2;
        if (i < 0) {
            throw new IllegalArgumentException("negative start index");
        }
        if (i2 < i) {
            throw new IllegalArgumentException("end index greater than start");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0442n)) {
            return false;
        }
        C0442n c0442n = (C0442n) obj;
        return this.a == c0442n.a && this.b == c0442n.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Interval(start=");
        sb.append(this.a);
        sb.append(", end=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
