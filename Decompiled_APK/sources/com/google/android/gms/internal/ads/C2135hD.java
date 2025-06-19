package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Arrays;
import java.util.Locale;

/* renamed from: com.google.android.gms.internal.ads.hD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2135hD {
    public static final C2135hD h;
    public final int a;
    public final int b;
    public final int c;
    public final byte[] d;
    public final int e;
    public final int f;
    public int g;

    static {
        int i = -1;
        h = new C2135hD(1, 2, 3, i, i, null);
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
    }

    public /* synthetic */ C2135hD(int i, int i2, int i3, int i4, int i5, byte[] bArr) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = bArr;
        this.e = i4;
        this.f = i5;
    }

    public static int a(int i) {
        if (i == 1) {
            return 1;
        }
        if (i != 9) {
            return (i == 4 || i == 5 || i == 6 || i == 7) ? 2 : -1;
        }
        return 6;
    }

    public static int b(int i) {
        if (i == 1) {
            return 3;
        }
        if (i == 4) {
            return 10;
        }
        if (i == 13) {
            return 2;
        }
        if (i == 16) {
            return 6;
        }
        if (i != 18) {
            return (i == 6 || i == 7) ? 3 : -1;
        }
        return 7;
    }

    public static boolean e(C2135hD c2135hD) {
        if (c2135hD == null) {
            return true;
        }
        int i = c2135hD.a;
        if (i != -1 && i != 1 && i != 2) {
            return false;
        }
        int i2 = c2135hD.b;
        if (i2 != -1 && i2 != 2) {
            return false;
        }
        int i3 = c2135hD.c;
        if ((i3 != -1 && i3 != 3) || c2135hD.d != null) {
            return false;
        }
        int i4 = c2135hD.f;
        if (i4 != -1 && i4 != 8) {
            return false;
        }
        int i5 = c2135hD.e;
        return i5 == -1 || i5 == 8;
    }

    public static String f(int i) {
        return i != -1 ? i != 1 ? i != 2 ? android.support.v4.media.session.a.f(i, "Undefined color range ") : "Limited range" : "Full range" : "Unset color range";
    }

    public static String g(int i) {
        return i != -1 ? i != 6 ? i != 1 ? i != 2 ? android.support.v4.media.session.a.f(i, "Undefined color space ") : "BT601" : "BT709" : "BT2020" : "Unset color space";
    }

    public static String h(int i) {
        return i != -1 ? i != 10 ? i != 1 ? i != 2 ? i != 3 ? i != 6 ? i != 7 ? android.support.v4.media.session.a.f(i, "Undefined color transfer ") : "HLG" : "ST2084 PQ" : "SDR SMPTE 170M" : "sRGB" : "Linear" : "Gamma 2.2" : "Unset color transfer";
    }

    public final String c() {
        String str;
        String str2;
        int i;
        if (d()) {
            String strG = g(this.a);
            String strF = f(this.b);
            String strH = h(this.c);
            String str3 = Yo.a;
            Locale locale = Locale.US;
            str = strG + "/" + strF + "/" + strH;
        } else {
            str = "NA/NA/NA";
        }
        int i2 = this.e;
        if (i2 == -1 || (i = this.f) == -1) {
            str2 = "NA/NA";
        } else {
            str2 = i2 + "/" + i;
        }
        return android.support.v4.media.session.a.l(str, "/", str2);
    }

    public final boolean d() {
        return (this.a == -1 || this.b == -1 || this.c == -1) ? false : true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C2135hD.class == obj.getClass()) {
            C2135hD c2135hD = (C2135hD) obj;
            if (this.a == c2135hD.a && this.b == c2135hD.b && this.c == c2135hD.c && Arrays.equals(this.d, c2135hD.d) && this.e == c2135hD.e && this.f == c2135hD.f) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.g;
        if (i != 0) {
            return i;
        }
        int iHashCode = ((((Arrays.hashCode(this.d) + ((((((this.a + 527) * 31) + this.b) * 31) + this.c) * 31)) * 31) + this.e) * 31) + this.f;
        this.g = iHashCode;
        return iHashCode;
    }

    public final String toString() {
        String str;
        String strG = g(this.a);
        String strF = f(this.b);
        String strH = h(this.c);
        String str2 = "NA";
        int i = this.e;
        if (i != -1) {
            str = i + "bit Luma";
        } else {
            str = "NA";
        }
        int i2 = this.f;
        if (i2 != -1) {
            str2 = i2 + "bit Chroma";
        }
        boolean z = this.d != null;
        StringBuilder sbH = AbstractC0147y.h("ColorInfo(", strG, ", ", strF, ", ");
        sbH.append(strH);
        sbH.append(", ");
        sbH.append(z);
        sbH.append(", ");
        return androidx.compose.ui.node.B.j(sbH, str, ", ", str2, ")");
    }
}
