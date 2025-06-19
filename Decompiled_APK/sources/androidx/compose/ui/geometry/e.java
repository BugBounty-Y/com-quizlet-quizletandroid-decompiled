package androidx.compose.ui.geometry;

import com.google.android.gms.internal.mlkit_vision_barcode.P4;

/* loaded from: classes.dex */
public final class e {
    public final long a;

    public static final boolean a(long j, long j2) {
        return j == j2;
    }

    public static final float b(long j) {
        if (j != 9205357640488583168L) {
            return Float.intBitsToFloat((int) (j & 4294967295L));
        }
        throw new IllegalStateException("Size is unspecified");
    }

    public static final float c(long j) {
        if (j != 9205357640488583168L) {
            return Math.min(Float.intBitsToFloat((int) ((j >> 32) & 2147483647L)), Float.intBitsToFloat((int) (j & 2147483647L)));
        }
        throw new IllegalStateException("Size is unspecified");
    }

    public static final float d(long j) {
        if (j != 9205357640488583168L) {
            return Float.intBitsToFloat((int) (j >> 32));
        }
        throw new IllegalStateException("Size is unspecified");
    }

    public static final boolean e(long j) {
        if (j == 9205357640488583168L) {
            throw new IllegalStateException("Size is unspecified");
        }
        long j2 = j & (~((((-9223372034707292160L) & j) >>> 31) * (-1)));
        return ((j2 & 4294967295L) & (j2 >>> 32)) == 0;
    }

    public static String f(long j) {
        if (j == 9205357640488583168L) {
            return "Size.Unspecified";
        }
        return "Size(" + P4.e(d(j)) + ", " + P4.e(b(j)) + ')';
    }

    public final boolean equals(Object obj) {
        if (obj instanceof e) {
            return this.a == ((e) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return f(this.a);
    }
}
