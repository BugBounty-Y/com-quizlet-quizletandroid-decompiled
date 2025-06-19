package com.google.android.gms.internal.measurement;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.measurement.x2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3079x2 {
    public static final C3079x2 f = new C3079x2(0, new int[0], new Object[0], false);
    public int a;
    public int[] b;
    public Object[] c;
    public int d = -1;
    public boolean e;

    public C3079x2(int i, int[] iArr, Object[] objArr, boolean z) {
        this.a = i;
        this.b = iArr;
        this.c = objArr;
        this.e = z;
    }

    public static C3079x2 b() {
        return new C3079x2(0, new int[8], new Object[8], true);
    }

    public final int a() {
        int iQ;
        int iA;
        int iQ2;
        int i = this.d;
        if (i != -1) {
            return i;
        }
        int iX = 0;
        for (int i2 = 0; i2 < this.a; i2++) {
            int i3 = this.b[i2];
            int i4 = i3 >>> 3;
            int i5 = i3 & 7;
            if (i5 != 0) {
                if (i5 == 1) {
                    ((Long) this.c[i2]).getClass();
                    iQ2 = P1.q(i4 << 3) + 8;
                } else if (i5 == 2) {
                    int i6 = i4 << 3;
                    O1 o1 = (O1) this.c[i2];
                    int iQ3 = P1.q(i6);
                    int iC = o1.c();
                    iX = AbstractC1642h.x(iC, iC, iQ3, iX);
                } else if (i5 == 3) {
                    int iQ4 = P1.q(i4 << 3);
                    iQ = iQ4 + iQ4;
                    iA = ((C3079x2) this.c[i2]).a();
                } else {
                    if (i5 != 5) {
                        throw new IllegalStateException(new zzml());
                    }
                    ((Integer) this.c[i2]).getClass();
                    iQ2 = P1.q(i4 << 3) + 4;
                }
                iX = iQ2 + iX;
            } else {
                int i7 = i4 << 3;
                long jLongValue = ((Long) this.c[i2]).longValue();
                iQ = P1.q(i7);
                iA = P1.a(jLongValue);
            }
            iX = iA + iQ + iX;
        }
        this.d = iX;
        return iX;
    }

    public final void c(int i, Object obj) {
        if (!this.e) {
            throw new UnsupportedOperationException();
        }
        e(this.a + 1);
        int[] iArr = this.b;
        int i2 = this.a;
        iArr[i2] = i;
        this.c[i2] = obj;
        this.a = i2 + 1;
    }

    public final void d(C3005i2 c3005i2) {
        if (this.a != 0) {
            for (int i = 0; i < this.a; i++) {
                int i2 = this.b[i];
                Object obj = this.c[i];
                int i3 = i2 & 7;
                int i4 = i2 >>> 3;
                if (i3 == 0) {
                    ((P1) c3005i2.a).n(i4, ((Long) obj).longValue());
                } else if (i3 == 1) {
                    ((P1) c3005i2.a).f(i4, ((Long) obj).longValue());
                } else if (i3 == 2) {
                    ((P1) c3005i2.a).c(i4, (O1) obj);
                } else if (i3 == 3) {
                    ((P1) c3005i2.a).k(i4, 3);
                    ((C3079x2) obj).d(c3005i2);
                    ((P1) c3005i2.a).k(i4, 4);
                } else {
                    if (i3 != 5) {
                        throw new RuntimeException(new zzml());
                    }
                    ((P1) c3005i2.a).d(i4, ((Integer) obj).intValue());
                }
            }
        }
    }

    public final void e(int i) {
        int[] iArr = this.b;
        if (i > iArr.length) {
            int i2 = this.a;
            int i3 = (i2 / 2) + i2;
            if (i3 >= i) {
                i = i3;
            }
            if (i < 8) {
                i = 8;
            }
            this.b = Arrays.copyOf(iArr, i);
            this.c = Arrays.copyOf(this.c, i);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C3079x2)) {
            return false;
        }
        C3079x2 c3079x2 = (C3079x2) obj;
        int i = this.a;
        if (i == c3079x2.a) {
            int[] iArr = this.b;
            int[] iArr2 = c3079x2.b;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    Object[] objArr = this.c;
                    Object[] objArr2 = c3079x2.c;
                    int i3 = this.a;
                    for (int i4 = 0; i4 < i3; i4++) {
                        if (objArr[i4].equals(objArr2[i4])) {
                        }
                    }
                    return true;
                }
                if (iArr[i2] != iArr2[i2]) {
                    break;
                }
                i2++;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.a;
        int i2 = i + 527;
        int[] iArr = this.b;
        int iHashCode = 17;
        int i3 = 17;
        for (int i4 = 0; i4 < i; i4++) {
            i3 = (i3 * 31) + iArr[i4];
        }
        int i5 = ((i2 * 31) + i3) * 31;
        Object[] objArr = this.c;
        int i6 = this.a;
        for (int i7 = 0; i7 < i6; i7++) {
            iHashCode = (iHashCode * 31) + objArr[i7].hashCode();
        }
        return i5 + iHashCode;
    }
}
