package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.Arrays;

/* renamed from: com.google.android.gms.internal.ads.uB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2691uB {
    public static final C2691uB f = new C2691uB(0, new int[0], new Object[0], false);
    public int a;
    public int[] b;
    public Object[] c;
    public int d = -1;
    public boolean e;

    public C2691uB(int i, int[] iArr, Object[] objArr, boolean z) {
        this.a = i;
        this.b = iArr;
        this.c = objArr;
        this.e = z;
    }

    public static C2691uB b() {
        return new C2691uB(0, new int[8], new Object[8], true);
    }

    public final int a() {
        int iC;
        int iD;
        int iC2;
        int i = this.d;
        if (i != -1) {
            return i;
        }
        int iH = 0;
        for (int i2 = 0; i2 < this.a; i2++) {
            int i3 = this.b[i2];
            int i4 = i3 >>> 3;
            int i5 = i3 & 7;
            if (i5 != 0) {
                if (i5 == 1) {
                    ((Long) this.c[i2]).getClass();
                    iC2 = HA.C(i4 << 3) + 8;
                } else if (i5 == 2) {
                    int i6 = i4 << 3;
                    BA ba = (BA) this.c[i2];
                    int iC3 = HA.C(i6);
                    int iG = ba.g();
                    iH = AbstractC1642h.h(iG, iG, iC3, iH);
                } else if (i5 == 3) {
                    int iC4 = HA.C(i4 << 3);
                    iC = iC4 + iC4;
                    iD = ((C2691uB) this.c[i2]).a();
                } else {
                    if (i5 != 5) {
                        throw new IllegalStateException(new zzgzg());
                    }
                    ((Integer) this.c[i2]).getClass();
                    iC2 = HA.C(i4 << 3) + 4;
                }
                iH = iC2 + iH;
            } else {
                int i7 = i4 << 3;
                long jLongValue = ((Long) this.c[i2]).longValue();
                iC = HA.C(i7);
                iD = HA.D(jLongValue);
            }
            iH = iD + iC + iH;
        }
        this.d = iH;
        return iH;
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

    public final void d(C2586rt c2586rt) {
        if (this.a != 0) {
            for (int i = 0; i < this.a; i++) {
                int i2 = this.b[i];
                Object obj = this.c[i];
                int i3 = i2 & 7;
                int i4 = i2 >>> 3;
                if (i3 == 0) {
                    ((HA) c2586rt.b).T(i4, ((Long) obj).longValue());
                } else if (i3 == 1) {
                    ((HA) c2586rt.b).K(i4, ((Long) obj).longValue());
                } else if (i3 == 2) {
                    ((HA) c2586rt.b).H(i4, (BA) obj);
                } else if (i3 == 3) {
                    ((HA) c2586rt.b).Q(i4, 3);
                    ((C2691uB) obj).d(c2586rt);
                    ((HA) c2586rt.b).Q(i4, 4);
                } else {
                    if (i3 != 5) {
                        throw new RuntimeException(new zzgzg());
                    }
                    ((HA) c2586rt.b).I(i4, ((Integer) obj).intValue());
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
        if (obj == null || !(obj instanceof C2691uB)) {
            return false;
        }
        C2691uB c2691uB = (C2691uB) obj;
        int i = this.a;
        if (i == c2691uB.a) {
            int[] iArr = this.b;
            int[] iArr2 = c2691uB.b;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    Object[] objArr = this.c;
                    Object[] objArr2 = c2691uB.c;
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
