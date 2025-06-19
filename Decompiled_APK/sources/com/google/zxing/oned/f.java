package com.google.zxing.oned;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v;
import com.google.android.gms.measurement.internal.Z;
import com.google.zxing.FormatException;
import java.util.EnumMap;

/* loaded from: classes2.dex */
public final class f extends AbstractC3739v {
    public final /* synthetic */ int b;

    public /* synthetic */ f(int i) {
        this.b = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v
    public final boolean[] b(String str) {
        switch (this.b) {
            case 0:
                int length = str.length();
                if (length == 12) {
                    try {
                        str = str + h.b(str);
                    } catch (FormatException e) {
                        throw new IllegalArgumentException(e);
                    }
                } else {
                    if (length != 13) {
                        throw new IllegalArgumentException("Requested contents should be 12 or 13 digits long, but got ".concat(String.valueOf(length)));
                    }
                    try {
                        if (!h.a(str)) {
                            throw new IllegalArgumentException("Contents do not pass checksum");
                        }
                    } catch (FormatException unused) {
                        throw new IllegalArgumentException("Illegal contents");
                    }
                }
                int i = e.g[Character.digit(str.charAt(0), 10)];
                boolean[] zArr = new boolean[95];
                int iA = AbstractC3739v.a(zArr, 0, h.b, true);
                for (int i2 = 1; i2 <= 6; i2++) {
                    int iDigit = Character.digit(str.charAt(i2), 10);
                    if (((i >> (6 - i2)) & 1) == 1) {
                        iDigit += 10;
                    }
                    iA += AbstractC3739v.a(zArr, iA, h.f[iDigit], false);
                }
                int iA2 = AbstractC3739v.a(zArr, iA, h.c, false) + iA;
                for (int i3 = 7; i3 <= 12; i3++) {
                    iA2 += AbstractC3739v.a(zArr, iA2, h.e[Character.digit(str.charAt(i3), 10)], true);
                }
                AbstractC3739v.a(zArr, iA2, h.b, true);
                return zArr;
            case 1:
                int length2 = str.length();
                if (length2 == 7) {
                    try {
                        str = str + h.b(str);
                    } catch (FormatException e2) {
                        throw new IllegalArgumentException(e2);
                    }
                } else {
                    if (length2 != 8) {
                        throw new IllegalArgumentException("Requested contents should be 8 digits long, but got ".concat(String.valueOf(length2)));
                    }
                    try {
                        if (!h.a(str)) {
                            throw new IllegalArgumentException("Contents do not pass checksum");
                        }
                    } catch (FormatException unused2) {
                        throw new IllegalArgumentException("Illegal contents");
                    }
                }
                boolean[] zArr2 = new boolean[67];
                int iA3 = AbstractC3739v.a(zArr2, 0, h.b, true);
                for (int i4 = 0; i4 <= 3; i4++) {
                    iA3 += AbstractC3739v.a(zArr2, iA3, h.e[Character.digit(str.charAt(i4), 10)], false);
                }
                int iA4 = AbstractC3739v.a(zArr2, iA3, h.c, false) + iA3;
                for (int i5 = 4; i5 <= 7; i5++) {
                    iA4 += AbstractC3739v.a(zArr2, iA4, h.e[Character.digit(str.charAt(i5), 10)], true);
                }
                AbstractC3739v.a(zArr2, iA4, h.b, true);
                return zArr2;
            default:
                int length3 = str.length();
                if (length3 == 7) {
                    try {
                        str = str + h.b(e.c(str));
                    } catch (FormatException e3) {
                        throw new IllegalArgumentException(e3);
                    }
                } else {
                    if (length3 != 8) {
                        throw new IllegalArgumentException("Requested contents should be 8 digits long, but got ".concat(String.valueOf(length3)));
                    }
                    try {
                        if (!h.a(str)) {
                            throw new IllegalArgumentException("Contents do not pass checksum");
                        }
                    } catch (FormatException unused3) {
                        throw new IllegalArgumentException("Illegal contents");
                    }
                }
                int iDigit2 = Character.digit(str.charAt(0), 10);
                if (iDigit2 != 0 && iDigit2 != 1) {
                    throw new IllegalArgumentException("Number system must be 0 or 1");
                }
                int i6 = e.h[iDigit2][Character.digit(str.charAt(7), 10)];
                boolean[] zArr3 = new boolean[51];
                int iA5 = AbstractC3739v.a(zArr3, 0, h.b, true);
                for (int i7 = 1; i7 <= 6; i7++) {
                    int iDigit3 = Character.digit(str.charAt(i7), 10);
                    if (((i6 >> (6 - i7)) & 1) == 1) {
                        iDigit3 += 10;
                    }
                    iA5 += AbstractC3739v.a(zArr3, iA5, h.f[iDigit3], false);
                }
                AbstractC3739v.a(zArr3, iA5, h.d, false);
                return zArr3;
        }
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v
    public final int c() {
        return 9;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v, com.google.zxing.b
    public final com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) {
        switch (this.b) {
            case 0:
                if (i == 8) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode EAN_13, but got ".concat(Z.t(i)));
            case 1:
                if (i == 7) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode EAN_8, but got ".concat(Z.t(i)));
            default:
                if (i == 16) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode UPC_E, but got ".concat(Z.t(i)));
        }
    }
}
