package kotlin.random;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public abstract class e {

    @NotNull
    public static final d a = new d(null);
    public static final a b;

    static {
        Integer num = kotlin.internal.jdk8.a.b;
        b = (num == null || num.intValue() >= 34) ? new kotlin.random.jdk8.a() : new b();
    }

    public abstract int a(int i);

    public double b() {
        return ((a(26) << 27) + a(27)) / 9.007199254740992E15d;
    }

    public int c() {
        return a(32);
    }

    public int d(int i) {
        return e(0, i);
    }

    public int e(int i, int i2) {
        int iC;
        int i3;
        int iA;
        if (i2 <= i) {
            throw new IllegalArgumentException(AbstractC3348i.e(Integer.valueOf(i), Integer.valueOf(i2)).toString());
        }
        int i4 = i2 - i;
        if (i4 > 0 || i4 == Integer.MIN_VALUE) {
            if (((-i4) & i4) == i4) {
                iA = a(31 - Integer.numberOfLeadingZeros(i4));
            } else {
                do {
                    iC = c() >>> 1;
                    i3 = iC % i4;
                } while ((i4 - 1) + (iC - i3) < 0);
                iA = i3;
            }
            return i + iA;
        }
        while (true) {
            int iC2 = c();
            if (i <= iC2 && iC2 < i2) {
                return iC2;
            }
        }
    }

    public long f() {
        return (c() << 32) + c();
    }

    public long g(long j, long j2) {
        long jF;
        long j3;
        long jA;
        int iC;
        if (j2 <= j) {
            throw new IllegalArgumentException(AbstractC3348i.e(Long.valueOf(j), Long.valueOf(j2)).toString());
        }
        long j4 = j2 - j;
        if (j4 > 0) {
            if (((-j4) & j4) == j4) {
                int i = (int) j4;
                int i2 = (int) (j4 >>> 32);
                if (i != 0) {
                    iC = a(31 - Integer.numberOfLeadingZeros(i));
                } else if (i2 == 1) {
                    iC = c();
                } else {
                    jA = (a(31 - Integer.numberOfLeadingZeros(i2)) << 32) + (c() & 4294967295L);
                }
                jA = iC & 4294967295L;
            } else {
                do {
                    jF = f() >>> 1;
                    j3 = jF % j4;
                } while ((j4 - 1) + (jF - j3) < 0);
                jA = j3;
            }
            return j + jA;
        }
        while (true) {
            long jF2 = f();
            if (j <= jF2 && jF2 < j2) {
                return jF2;
            }
        }
    }

    public long h() {
        return g(0L, 1000L);
    }
}
