package androidx.work;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class M {
    public final long a;
    public final long b;

    public M(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && M.class.equals(obj.getClass())) {
            M m = (M) obj;
            if (m.a == this.a && m.b == this.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PeriodicityInfo{repeatIntervalMillis=");
        sb.append(this.a);
        sb.append(", flexIntervalMillis=");
        return d0.q(sb, this.b, '}');
    }
}
