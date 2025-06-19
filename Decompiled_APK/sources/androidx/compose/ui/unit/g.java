package androidx.compose.ui.unit;

/* loaded from: classes.dex */
public final class g {
    public final long a;

    public static final float a(long j) {
        return Float.intBitsToFloat((int) (j & 4294967295L));
    }

    public static final float b(long j) {
        return Float.intBitsToFloat((int) (j >> 32));
    }

    public static String c(long j) {
        if (j == 9205357640488583168L) {
            return "DpSize.Unspecified";
        }
        return ((Object) e.b(b(j))) + " x " + ((Object) e.b(a(j)));
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
        return c(this.a);
    }
}
