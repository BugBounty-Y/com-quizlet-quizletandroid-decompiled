package com.google.zxing.oned;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v;
import com.google.android.gms.measurement.internal.Z;
import java.util.EnumMap;

/* loaded from: classes2.dex */
public final class g extends AbstractC3739v {
    public static final int[] c = {1, 1, 1, 1};
    public static final int[] d = {3, 1, 1};
    public static final int[][] e = {new int[]{1, 1, 3, 3, 1}, new int[]{3, 1, 1, 1, 3}, new int[]{1, 3, 1, 1, 3}, new int[]{3, 3, 1, 1, 1}, new int[]{1, 1, 3, 1, 3}, new int[]{3, 1, 3, 1, 1}, new int[]{1, 3, 3, 1, 1}, new int[]{1, 1, 1, 3, 3}, new int[]{3, 1, 1, 3, 1}, new int[]{1, 3, 1, 3, 1}};
    public final /* synthetic */ int b;

    public /* synthetic */ g(int i) {
        this.b = i;
    }

    public static void d(boolean[] zArr, int i, int[] iArr) {
        int length = iArr.length;
        int i2 = 0;
        while (i2 < length) {
            int i3 = i + 1;
            zArr[i] = iArr[i2] != 0;
            i2++;
            i = i3;
        }
    }

    public static int e(int i, String str) {
        int iIndexOf = 0;
        int i2 = 1;
        for (int length = str.length() - 1; length >= 0; length--) {
            iIndexOf += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%abcd*".indexOf(str.charAt(length)) * i2;
            i2++;
            if (i2 > i) {
                i2 = 1;
            }
        }
        return iIndexOf % 47;
    }

    public static int f(int i, String str) {
        char cCharAt;
        int length = str.length();
        if (i < length) {
            char cCharAt2 = str.charAt(i);
            if (cCharAt2 == 241) {
                return 4;
            }
            if (cCharAt2 >= '0' && cCharAt2 <= '9') {
                int i2 = i + 1;
                return (i2 < length && (cCharAt = str.charAt(i2)) >= '0' && cCharAt <= '9') ? 3 : 2;
            }
        }
        return 1;
    }

    public static void g(int[] iArr, int i) {
        for (int i2 = 0; i2 < 9; i2++) {
            int i3 = 1;
            if (((1 << (8 - i2)) & i) != 0) {
                i3 = 2;
            }
            iArr[i2] = i3;
        }
    }

    public static void h(int[] iArr, int i) {
        for (int i2 = 0; i2 < 9; i2++) {
            int i3 = 1;
            if (((1 << (8 - i2)) & i) == 0) {
                i3 = 0;
            }
            iArr[i2] = i3;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:136:0x029f  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0184  */
    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean[] b(java.lang.String r19) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 1022
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.zxing.oned.g.b(java.lang.String):boolean[]");
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3739v, com.google.zxing.b
    public final com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) {
        switch (this.b) {
            case 0:
                if (i == 9) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode ITF, but got ".concat(Z.t(i)));
            case 1:
                if (i == 5) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode CODE_128, but got ".concat(Z.t(i)));
            case 2:
                if (i == 3) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode CODE_39, but got ".concat(Z.t(i)));
            default:
                if (i == 4) {
                    return super.l(str, i, i2, i3, enumMap);
                }
                throw new IllegalArgumentException("Can only encode CODE_93, but got ".concat(Z.t(i)));
        }
    }
}
