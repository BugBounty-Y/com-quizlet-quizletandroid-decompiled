package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class JF implements XF {
    public final J9 a;
    public final int b;
    public final int[] c;
    public final C1832aG[] d;
    public int e;

    public JF(J9 j9, int[] iArr) {
        C1832aG[] c1832aGArr;
        int length = iArr.length;
        AbstractC1795We.L(length > 0);
        j9.getClass();
        this.a = j9;
        this.b = length;
        this.d = new C1832aG[length];
        int i = 0;
        while (true) {
            int length2 = iArr.length;
            c1832aGArr = j9.d;
            if (i >= length2) {
                break;
            }
            this.d[i] = c1832aGArr[iArr[i]];
            i++;
        }
        Arrays.sort(this.d, new B2(5));
        this.c = new int[this.b];
        for (int i2 = 0; i2 < this.b; i2++) {
            int[] iArr2 = this.c;
            C1832aG c1832aG = this.d[i2];
            int i3 = 0;
            while (true) {
                if (i3 >= c1832aGArr.length) {
                    i3 = -1;
                    break;
                } else if (c1832aG == c1832aGArr[i3]) {
                    break;
                } else {
                    i3++;
                }
            }
            iArr2[i2] = i3;
        }
    }

    public static void b(ArrayList arrayList, long[] jArr) {
        long j = 0;
        for (int i = 0; i < 2; i++) {
            j += jArr[i];
        }
        for (int i2 = 0; i2 < arrayList.size(); i2++) {
            C2159hu c2159hu = (C2159hu) arrayList.get(i2);
            if (c2159hu != null) {
                c2159hu.c(new IF(j, jArr[i2]));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final J9 a() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int e(int i) {
        for (int i2 = 0; i2 < this.b; i2++) {
            if (this.c[i2] == i) {
                return i2;
            }
        }
        return -1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            JF jf = (JF) obj;
            if (this.a.equals(jf.a) && Arrays.equals(this.c, jf.c)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int f() {
        return this.c[0];
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int g() {
        return this.c.length;
    }

    public final int hashCode() {
        int i = this.e;
        if (i != 0) {
            return i;
        }
        int iHashCode = Arrays.hashCode(this.c) + (System.identityHashCode(this.a) * 31);
        this.e = iHashCode;
        return iHashCode;
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final int u(int i) {
        return this.c[i];
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final C1832aG zza(int i) {
        return this.d[i];
    }

    @Override // com.google.android.gms.internal.ads.XF
    public final C1832aG zzb() {
        return this.d[0];
    }
}
