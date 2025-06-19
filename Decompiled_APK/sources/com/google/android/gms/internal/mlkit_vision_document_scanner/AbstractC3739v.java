package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.EnumMap;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3739v implements com.google.zxing.b {
    public static final /* synthetic */ int a = 0;

    public static int a(boolean[] zArr, int i, int[] iArr, boolean z) {
        int i2 = 0;
        for (int i3 : iArr) {
            int i4 = 0;
            while (i4 < i3) {
                zArr[i] = z;
                i4++;
                i++;
            }
            i2 += i3;
            z = !z;
        }
        return i2;
    }

    public abstract boolean[] b(String str);

    public int c() {
        return 10;
    }

    @Override // com.google.zxing.b
    public com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) throws NumberFormatException {
        if (str.isEmpty()) {
            throw new IllegalArgumentException("Found empty contents");
        }
        if (i2 < 0 || i3 < 0) {
            throw new IllegalArgumentException("Negative size is not allowed. Input: " + i2 + 'x' + i3);
        }
        int iC = c();
        com.google.zxing.a aVar = com.google.zxing.a.f;
        if (enumMap.containsKey(aVar)) {
            iC = Integer.parseInt(enumMap.get(aVar).toString());
        }
        boolean[] zArrB = b(str);
        int length = zArrB.length;
        int i4 = iC + length;
        int iMax = Math.max(i2, i4);
        int iMax2 = Math.max(1, i3);
        int i5 = iMax / i4;
        int i6 = (iMax - (length * i5)) / 2;
        com.google.zxing.common.b bVar = new com.google.zxing.common.b(iMax, iMax2);
        int i7 = 0;
        while (i7 < length) {
            if (zArrB[i7]) {
                bVar.d(i6, 0, i5, iMax2);
            }
            i7++;
            i6 += i5;
        }
        return bVar;
    }
}
