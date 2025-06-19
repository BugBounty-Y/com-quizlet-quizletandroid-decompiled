package kotlin.time;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class b implements Comparable {

    @NotNull
    public static final a b = new a(null);
    public static final long c;
    public static final long d;
    public final long a;

    static {
        int i = c.a;
        c = AbstractC3397u1.b(4611686018427387903L);
        d = AbstractC3397u1.b(-4611686018427387903L);
    }

    public static final long a(long j, long j2) {
        long j3 = 1000000;
        long j4 = j2 / j3;
        long j5 = j + j4;
        if (-4611686018426L > j5 || j5 >= 4611686018427L) {
            return AbstractC3397u1.b(l.d(j5, -4611686018427387903L, 4611686018427387903L));
        }
        return AbstractC3397u1.d((j5 * j3) + (j2 - (j4 * j3)));
    }

    public static final void b(StringBuilder sb, int i, int i2, int i3, String str, boolean z) {
        sb.append(i);
        if (i2 != 0) {
            sb.append('.');
            String strS = StringsKt.S('0', i3, String.valueOf(i2));
            int i4 = -1;
            int length = strS.length() - 1;
            if (length >= 0) {
                while (true) {
                    int i5 = length - 1;
                    if (strS.charAt(length) != '0') {
                        i4 = length;
                        break;
                    } else if (i5 < 0) {
                        break;
                    } else {
                        length = i5;
                    }
                }
            }
            int i6 = i4 + 1;
            if (z || i6 >= 3) {
                sb.append((CharSequence) strS, 0, ((i4 + 3) / 3) * 3);
                Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
            } else {
                sb.append((CharSequence) strS, 0, i6);
                Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
            }
        }
        sb.append(str);
    }

    public static int c(long j, long j2) {
        long j3 = j ^ j2;
        if (j3 < 0 || (((int) j3) & 1) == 0) {
            return Intrinsics.h(j, j2);
        }
        int i = (((int) j) & 1) - (((int) j2) & 1);
        return j < 0 ? -i : i;
    }

    public static final boolean d(long j, long j2) {
        return j == j2;
    }

    public static final long e(long j) {
        return ((((int) j) & 1) != 1 || g(j)) ? i(j, d.c) : j >> 1;
    }

    public static final int f(long j) {
        if (g(j)) {
            return 0;
        }
        return (((int) j) & 1) == 1 ? (int) (((j >> 1) % 1000) * 1000000) : (int) ((j >> 1) % 1000000000);
    }

    public static final boolean g(long j) {
        return j == c || j == d;
    }

    public static final long h(long j, long j2) {
        if (g(j)) {
            if (!g(j2) || (j2 ^ j) >= 0) {
                return j;
            }
            throw new IllegalArgumentException("Summing infinite durations of different signs yields an undefined result.");
        }
        if (g(j2)) {
            return j2;
        }
        int i = ((int) j) & 1;
        if (i != (((int) j2) & 1)) {
            return i == 1 ? a(j >> 1, j2 >> 1) : a(j2 >> 1, j >> 1);
        }
        long j3 = (j >> 1) + (j2 >> 1);
        return i == 0 ? (-4611686018426999999L > j3 || j3 >= 4611686018427000000L) ? AbstractC3397u1.b(j3 / 1000000) : AbstractC3397u1.d(j3) : AbstractC3397u1.c(j3);
    }

    public static final long i(long j, d unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        if (j == c) {
            return Long.MAX_VALUE;
        }
        if (j == d) {
            return Long.MIN_VALUE;
        }
        return e.b(j >> 1, (((int) j) & 1) == 0 ? d.b : d.c, unit);
    }

    public static String j(long j) {
        long j2;
        int i;
        if (j == 0) {
            return "0s";
        }
        if (j == c) {
            return "Infinity";
        }
        if (j == d) {
            return "-Infinity";
        }
        int i2 = 0;
        boolean z = j < 0;
        StringBuilder sb = new StringBuilder();
        if (z) {
            sb.append('-');
        }
        long jK = j < 0 ? k(j) : j;
        long jI = i(jK, d.g);
        int i3 = g(jK) ? 0 : (int) (i(jK, d.f) % 24);
        if (g(jK)) {
            j2 = 0;
            i = 0;
        } else {
            j2 = 0;
            i = (int) (i(jK, d.e) % 60);
        }
        int i4 = g(jK) ? 0 : (int) (i(jK, d.d) % 60);
        int iF = f(jK);
        boolean z2 = jI != j2;
        boolean z3 = i3 != 0;
        boolean z4 = i != 0;
        boolean z5 = (i4 == 0 && iF == 0) ? false : true;
        if (z2) {
            sb.append(jI);
            sb.append('d');
            i2 = 1;
        }
        if (z3 || (z2 && (z4 || z5))) {
            int i5 = i2 + 1;
            if (i2 > 0) {
                sb.append(' ');
            }
            sb.append(i3);
            sb.append('h');
            i2 = i5;
        }
        if (z4 || (z5 && (z3 || z2))) {
            int i6 = i2 + 1;
            if (i2 > 0) {
                sb.append(' ');
            }
            sb.append(i);
            sb.append('m');
            i2 = i6;
        }
        if (z5) {
            int i7 = i2 + 1;
            if (i2 > 0) {
                sb.append(' ');
            }
            if (i4 != 0 || z2 || z3 || z4) {
                b(sb, i4, iF, 9, "s", false);
            } else if (iF >= 1000000) {
                b(sb, iF / 1000000, iF % 1000000, 6, "ms", false);
            } else if (iF >= 1000) {
                b(sb, iF / 1000, iF % 1000, 3, OTCCPAGeolocationConstants.US, false);
            } else {
                sb.append(iF);
                sb.append("ns");
            }
            i2 = i7;
        }
        if (z && i2 > 1) {
            sb.insert(1, '(').append(')');
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public static final long k(long j) {
        long j2 = ((-(j >> 1)) << 1) + (((int) j) & 1);
        int i = c.a;
        return j2;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return c(this.a, ((b) obj).a);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            return this.a == ((b) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return j(this.a);
    }
}
