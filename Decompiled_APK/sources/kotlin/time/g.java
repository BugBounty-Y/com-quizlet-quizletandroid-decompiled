package kotlin.time;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3401v1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements TimeMark, Comparable {
    public final long a;

    @Override // kotlin.time.TimeMark
    public final long a() {
        f.a.getClass();
        long jNanoTime = System.nanoTime() - f.b;
        d unit = d.b;
        Intrinsics.checkNotNullParameter(unit, "unit");
        long j = this.a;
        return (1 | (j - 1)) == Long.MAX_VALUE ? b.k(AbstractC3401v1.b(j)) : AbstractC3401v1.c(jNanoTime, j, unit);
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        long jB;
        g other = (g) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(other, "other");
        Intrinsics.checkNotNullParameter(other, "other");
        boolean z = other instanceof g;
        long j = this.a;
        if (!z) {
            throw new IllegalArgumentException("Subtracting or comparing time marks from different time sources is not possible: " + ((Object) ("ValueTimeMark(reading=" + j + ')')) + " and " + other);
        }
        long j2 = other.a;
        f.a.getClass();
        d unit = d.b;
        Intrinsics.checkNotNullParameter(unit, "unit");
        if (((j2 - 1) | 1) != Long.MAX_VALUE) {
            jB = (1 | (j - 1)) == Long.MAX_VALUE ? AbstractC3401v1.b(j) : AbstractC3401v1.c(j, j2, unit);
        } else if (j == j2) {
            b.b.getClass();
            jB = 0;
        } else {
            jB = b.k(AbstractC3401v1.b(j2));
        }
        b.b.getClass();
        return b.c(jB, 0L);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof g) {
            return this.a == ((g) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "ValueTimeMark(reading=" + this.a + ')';
    }
}
