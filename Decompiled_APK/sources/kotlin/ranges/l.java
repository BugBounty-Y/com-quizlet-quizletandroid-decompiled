package kotlin.ranges;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class l extends k {
    public static double a(double d, double d2, double d3) {
        if (d2 <= d3) {
            return d < d2 ? d2 : d > d3 ? d3 : d;
        }
        throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + d3 + " is less than minimum " + d2 + '.');
    }

    public static float b(float f, float f2, float f3) {
        if (f2 <= f3) {
            return f < f2 ? f2 : f > f3 ? f3 : f;
        }
        throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + f3 + " is less than minimum " + f2 + '.');
    }

    public static int c(int i, int i2, int i3) {
        if (i2 <= i3) {
            return i < i2 ? i2 : i > i3 ? i3 : i;
        }
        throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + i3 + " is less than minimum " + i2 + '.');
    }

    public static long d(long j, long j2, long j3) {
        if (j2 <= j3) {
            return j < j2 ? j2 : j > j3 ? j3 : j;
        }
        throw new IllegalArgumentException(d0.q(d0.t(j3, "Cannot coerce value to an empty range: maximum ", " is less than minimum "), j2, '.'));
    }

    public static Comparable e(Float f, f range) {
        Intrinsics.checkNotNullParameter(f, "<this>");
        Intrinsics.checkNotNullParameter(range, "range");
        float f2 = range.a;
        float f3 = range.b;
        if (f2 <= f3) {
            return (!f.a(f, Float.valueOf(f2)) || f.a(Float.valueOf(f2), f)) ? (!f.a(Float.valueOf(f3), f) || f.a(f, Float.valueOf(f3))) ? f : Float.valueOf(f3) : Float.valueOf(f2);
        }
        throw new IllegalArgumentException("Cannot coerce value to an empty range: " + range + '.');
    }

    public static Comparable f(Integer num, Integer num2, Integer num3) {
        Intrinsics.checkNotNullParameter(num, "<this>");
        if (num2 == null || num3 == null) {
            if (num2 != null && num.compareTo(num2) < 0) {
                return num2;
            }
            if (num3 != null && num.compareTo(num3) > 0) {
                return num3;
            }
        } else {
            if (num2.compareTo(num3) > 0) {
                throw new IllegalArgumentException("Cannot coerce value to an empty range: maximum " + num3 + " is less than minimum " + num2 + '.');
            }
            if (num.compareTo(num2) < 0) {
                return num2;
            }
            if (num.compareTo(num3) > 0) {
                return num3;
            }
        }
        return num;
    }

    public static h g(int i, IntRange intRange) {
        Intrinsics.checkNotNullParameter(intRange, "<this>");
        boolean z = i > 0;
        Integer step = Integer.valueOf(i);
        Intrinsics.checkNotNullParameter(step, "step");
        if (!z) {
            throw new IllegalArgumentException("Step must be positive, was: " + step + '.');
        }
        g gVar = h.d;
        int i2 = intRange.a;
        if (intRange.c <= 0) {
            i = -i;
        }
        gVar.getClass();
        return new h(i2, intRange.b, i);
    }

    public static IntRange h(int i, int i2) {
        if (i2 > Integer.MIN_VALUE) {
            return new IntRange(i, i2 - 1, 1);
        }
        IntRange.e.getClass();
        return IntRange.f;
    }
}
