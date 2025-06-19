package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class J9 {
    public final int a;
    public final String b;
    public final int c;
    public final C1832aG[] d;
    public int e;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
    }

    public J9(String str, C1832aG... c1832aGArr) {
        int length = c1832aGArr.length;
        int i = 1;
        AbstractC1795We.B(length > 0);
        this.b = str;
        this.d = c1832aGArr;
        this.a = length;
        int iB = AbstractC2514q5.b(c1832aGArr[0].m);
        this.c = iB == -1 ? AbstractC2514q5.b(c1832aGArr[0].l) : iB;
        String str2 = c1832aGArr[0].d;
        str2 = (str2 == null || str2.equals("und")) ? "" : str2;
        int i2 = c1832aGArr[0].f | 16384;
        while (true) {
            C1832aG[] c1832aGArr2 = this.d;
            if (i >= c1832aGArr2.length) {
                return;
            }
            String str3 = c1832aGArr2[i].d;
            if (!str2.equals((str3 == null || str3.equals("und")) ? "" : str3)) {
                C1832aG[] c1832aGArr3 = this.d;
                a("languages", i, c1832aGArr3[0].d, c1832aGArr3[i].d);
                return;
            } else {
                C1832aG[] c1832aGArr4 = this.d;
                if (i2 != (c1832aGArr4[i].f | 16384)) {
                    a("role flags", i, Integer.toBinaryString(c1832aGArr4[0].f), Integer.toBinaryString(this.d[i].f));
                    return;
                }
                i++;
            }
        }
    }

    public static void a(String str, int i, String str2, String str3) {
        StringBuilder sbH = AbstractC0147y.h("Different ", str, " combined in one TrackGroup: '", str2, "' (track 0) and '");
        sbH.append(str3);
        sbH.append("' (track ");
        sbH.append(i);
        sbH.append(")");
        AbstractC2096gb.A("TrackGroup", "", new IllegalStateException(sbH.toString()));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && J9.class == obj.getClass()) {
            J9 j9 = (J9) obj;
            if (this.b.equals(j9.b) && Arrays.equals(this.d, j9.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.e;
        if (i != 0) {
            return i;
        }
        int iHashCode = Arrays.hashCode(this.d) + ((this.b.hashCode() + 527) * 31);
        this.e = iHashCode;
        return iHashCode;
    }

    public final String toString() {
        return AbstractC0147y.g(new StringBuilder(), this.b, ": ", Arrays.toString(this.d));
    }
}
