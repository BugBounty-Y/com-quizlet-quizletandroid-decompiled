package com.google.zxing.aztec.encoder;

/* loaded from: classes2.dex */
public abstract class b {
    public static final int[] a = {4, 6, 6, 8, 8, 8, 8, 8, 8, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12};

    public static void a(com.google.zxing.common.b bVar, int i, int i2) {
        for (int i3 = 0; i3 < i2; i3 += 2) {
            int i4 = i - i3;
            int i5 = i4;
            while (true) {
                int i6 = i + i3;
                if (i5 <= i6) {
                    bVar.c(i5, i4);
                    bVar.c(i5, i6);
                    bVar.c(i4, i5);
                    bVar.c(i6, i5);
                    i5++;
                }
            }
        }
        int i7 = i - i2;
        bVar.c(i7, i7);
        int i8 = i7 + 1;
        bVar.c(i8, i7);
        bVar.c(i7, i8);
        int i9 = i + i2;
        bVar.c(i9, i7);
        bVar.c(i9, i8);
        bVar.c(i9, i9 - 1);
    }

    public static com.google.zxing.common.a b(com.google.zxing.common.a aVar, int i, int i2) {
        com.google.zxing.common.reedsolomon.a aVar2;
        int i3 = aVar.b / i2;
        if (i2 == 4) {
            aVar2 = com.google.zxing.common.reedsolomon.a.j;
        } else if (i2 == 6) {
            aVar2 = com.google.zxing.common.reedsolomon.a.i;
        } else if (i2 == 8) {
            aVar2 = com.google.zxing.common.reedsolomon.a.l;
        } else if (i2 == 10) {
            aVar2 = com.google.zxing.common.reedsolomon.a.h;
        } else {
            if (i2 != 12) {
                throw new IllegalArgumentException("Unsupported word size ".concat(String.valueOf(i2)));
            }
            aVar2 = com.google.zxing.common.reedsolomon.a.g;
        }
        com.quizlet.data.repository.activitycenter.b bVar = new com.quizlet.data.repository.activitycenter.b(aVar2);
        int i4 = i / i2;
        int[] iArr = new int[i4];
        int i5 = aVar.b / i2;
        for (int i6 = 0; i6 < i5; i6++) {
            int i7 = 0;
            for (int i8 = 0; i8 < i2; i8++) {
                i7 |= aVar.e((i6 * i2) + i8) ? 1 << ((i2 - i8) - 1) : 0;
            }
            iArr[i6] = i7;
        }
        bVar.f(iArr, i4 - i3);
        com.google.zxing.common.a aVar3 = new com.google.zxing.common.a();
        aVar3.c(0, i % i2);
        for (int i9 = 0; i9 < i4; i9++) {
            aVar3.c(iArr[i9], i2);
        }
        return aVar3;
    }

    public static com.google.zxing.common.a c(com.google.zxing.common.a aVar, int i) {
        com.google.zxing.common.a aVar2 = new com.google.zxing.common.a();
        int i2 = aVar.b;
        int i3 = (1 << i) - 2;
        int i4 = 0;
        while (i4 < i2) {
            int i5 = 0;
            for (int i6 = 0; i6 < i; i6++) {
                int i7 = i4 + i6;
                if (i7 >= i2 || aVar.e(i7)) {
                    i5 |= 1 << ((i - 1) - i6);
                }
            }
            int i8 = i5 & i3;
            if (i8 == i3) {
                aVar2.c(i8, i);
            } else if (i8 == 0) {
                aVar2.c(i5 | 1, i);
            } else {
                aVar2.c(i5, i);
                i4 += i;
            }
            i4--;
            i4 += i;
        }
        return aVar2;
    }
}
