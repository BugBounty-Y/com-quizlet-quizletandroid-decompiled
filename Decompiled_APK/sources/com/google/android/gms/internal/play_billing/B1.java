package com.google.android.gms.internal.play_billing;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class B1 {
    public static final B1 f = new B1(0, new int[0], new Object[0], false);
    public int a;
    public int[] b;
    public Object[] c;
    public int d = -1;
    public boolean e;

    public B1(int i, int[] iArr, Object[] objArr, boolean z) {
        this.a = i;
        this.b = iArr;
        this.c = objArr;
        this.e = z;
    }

    public static B1 b() {
        return new B1(0, new int[8], new Object[8], true);
    }

    public final int a() {
        int iE0;
        int iO;
        int iE02;
        int i = this.d;
        if (i != -1) {
            return i;
        }
        int iZ = 0;
        for (int i2 = 0; i2 < this.a; i2++) {
            int i3 = this.b[i2];
            int i4 = i3 >>> 3;
            int i5 = i3 & 7;
            if (i5 != 0) {
                if (i5 == 1) {
                    ((Long) this.c[i2]).getClass();
                    iE02 = V0.e0(i4 << 3) + 8;
                } else if (i5 == 2) {
                    int i6 = i4 << 3;
                    U0 u0 = (U0) this.c[i2];
                    int iE03 = V0.e0(i6);
                    int iC = u0.c();
                    iZ = AbstractC1642h.z(iC, iC, iE03, iZ);
                } else if (i5 == 3) {
                    int iE04 = V0.e0(i4 << 3);
                    iE0 = iE04 + iE04;
                    iO = ((B1) this.c[i2]).a();
                } else {
                    if (i5 != 5) {
                        throw new IllegalStateException(new zzhq());
                    }
                    ((Integer) this.c[i2]).getClass();
                    iE02 = V0.e0(i4 << 3) + 4;
                }
                iZ = iE02 + iZ;
            } else {
                int i7 = i4 << 3;
                long jLongValue = ((Long) this.c[i2]).longValue();
                iE0 = V0.e0(i7);
                iO = V0.O(jLongValue);
            }
            iZ = iO + iE0 + iZ;
        }
        this.d = iZ;
        return iZ;
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

    public final void d(C3817m1 c3817m1) {
        if (this.a != 0) {
            for (int i = 0; i < this.a; i++) {
                int i2 = this.b[i];
                Object obj = this.c[i];
                int i3 = i2 & 7;
                int i4 = i2 >>> 3;
                if (i3 == 0) {
                    ((V0) c3817m1.a).b0(i4, ((Long) obj).longValue());
                } else if (i3 == 1) {
                    ((V0) c3817m1.a).T(i4, ((Long) obj).longValue());
                } else if (i3 == 2) {
                    ((V0) c3817m1.a).Q(i4, (U0) obj);
                } else if (i3 == 3) {
                    ((V0) c3817m1.a).Y(i4, 3);
                    ((B1) obj).d(c3817m1);
                    ((V0) c3817m1.a).Y(i4, 4);
                } else {
                    if (i3 != 5) {
                        throw new RuntimeException(new zzhq());
                    }
                    ((V0) c3817m1.a).R(i4, ((Integer) obj).intValue());
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
        if (obj == null || !(obj instanceof B1)) {
            return false;
        }
        B1 b1 = (B1) obj;
        int i = this.a;
        if (i == b1.a) {
            int[] iArr = this.b;
            int[] iArr2 = b1.b;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    Object[] objArr = this.c;
                    Object[] objArr2 = b1.c;
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
