package com.sdk.growthbook.utils;

import com.google.android.gms.internal.mlkit_vision_barcode.H6;
import com.soywiz.krypto.b;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.e;
import kotlin.ranges.h;
import kotlin.ranges.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class DefaultCrypto implements Crypto {

    @NotNull
    private final b padding = b.b;

    @Override // com.sdk.growthbook.utils.Crypto
    @NotNull
    public byte[] decrypt(@NotNull byte[] cipherText, @NotNull byte[] key, @NotNull byte[] iv) {
        Intrinsics.checkNotNullParameter(cipherText, "cipherText");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(iv, "iv");
        int[] iArr = com.soywiz.krypto.a.g;
        b bVar = this.padding;
        com.soywiz.krypto.a aVar = new com.soywiz.krypto.a(key);
        int[] iArrI = H6.i(cipherText);
        int length = iArrI.length;
        byte[] bArr = new byte[16];
        boolean z = false;
        if (iv != null) {
            C4930v.d(0, 0, iv.length < 16 ? iv.length : 16, iv, bArr);
        }
        int[] iArrI2 = H6.i(bArr);
        int i = iArrI2[0];
        int i2 = iArrI2[1];
        int i3 = iArrI2[2];
        int i4 = iArrI2[3];
        char c = 4;
        h hVarG = l.g(4, l.h(0, length));
        int i5 = hVarG.a;
        int i6 = hVarG.b;
        int i7 = hVarG.c;
        if ((i7 > 0 && i5 <= i6) || (i7 < 0 && i6 <= i5)) {
            int i8 = i2;
            int i9 = i3;
            int i10 = i5;
            while (true) {
                int i11 = i10 + i7;
                int i12 = iArrI[i10];
                int i13 = i10 + 1;
                int i14 = iArrI[i13];
                int i15 = i10 + 2;
                int i16 = iArrI[i15];
                int i17 = i10 + 3;
                int i18 = iArrI[i17];
                iArrI[i13] = i18;
                iArrI[i17] = i14;
                int i19 = i6;
                aVar.a(iArrI, i10, aVar.f, com.soywiz.krypto.a.m, com.soywiz.krypto.a.n, com.soywiz.krypto.a.o, com.soywiz.krypto.a.p, com.soywiz.krypto.a.h);
                int i20 = iArrI[i13];
                iArrI[i13] = iArrI[i17];
                iArrI[i17] = i20;
                iArrI[i10] = i ^ iArrI[i10];
                iArrI[i13] = iArrI[i13] ^ i8;
                iArrI[i15] = iArrI[i15] ^ i9;
                iArrI[i17] = i4 ^ iArrI[i17];
                if (i10 == i19) {
                    break;
                }
                i6 = i19;
                i10 = i11;
                i = i12;
                i8 = i14;
                i9 = i16;
                i4 = i18;
                z = false;
                c = 4;
            }
        }
        byte[] bArrH = H6.h(iArrI);
        int iOrdinal = bVar.ordinal();
        if (iOrdinal == 0) {
            return bArrH;
        }
        if (iOrdinal == 1 || iOrdinal == 2 || iOrdinal == 3) {
            int length2 = bArrH.length - (bArrH[bArrH.length - 1] & 255);
            byte[] bArr2 = new byte[length2];
            C4930v.d(0, 0, length2, bArrH, bArr2);
            return bArr2;
        }
        if (iOrdinal != 4) {
            throw new NoWhenBranchMatchedException();
        }
        int length3 = bArrH.length - 1;
        int i21 = 0;
        if (length3 >= 0) {
            while (true) {
                int i22 = length3 - 1;
                if (bArrH[length3] != 0) {
                    break;
                }
                i21++;
                if (i22 < 0) {
                    break;
                }
                length3 = i22;
            }
        }
        int length4 = bArrH.length - i21;
        byte[] bArr3 = new byte[length4];
        C4930v.d(0, 0, length4, bArrH, bArr3);
        return bArr3;
    }

    @Override // com.sdk.growthbook.utils.Crypto
    @NotNull
    public byte[] encrypt(@NotNull byte[] inputText, @NotNull byte[] key, @NotNull byte[] iv) {
        int[] iArr;
        Intrinsics.checkNotNullParameter(inputText, "inputText");
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(iv, "iv");
        int[] iArr2 = com.soywiz.krypto.a.g;
        b bVar = this.padding;
        b bVar2 = b.a;
        int length = bVar == bVar2 ? 0 : 16 - (inputText.length % 16);
        int length2 = inputText.length + length;
        byte[] bArr = new byte[length2];
        C4930v.d(0, 0, inputText.length, inputText, bArr);
        int iOrdinal = bVar.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal == 1) {
                for (int length3 = inputText.length; length3 < length2; length3++) {
                    bArr[length3] = (byte) length;
                }
            } else if (iOrdinal == 2) {
                bArr[length2 - 1] = (byte) length;
            } else if (iOrdinal == 3) {
                e.a.getClass();
                kotlin.random.a aVar = e.b;
                aVar.getClass();
                byte[] array = new byte[length];
                Intrinsics.checkNotNullParameter(array, "array");
                aVar.j().nextBytes(array);
                array[length - 1] = (byte) length;
                C4930v.d(inputText.length, 0, length, array, bArr);
            } else if (iOrdinal != 4) {
                throw new NoWhenBranchMatchedException();
            }
        }
        com.soywiz.krypto.a aVar2 = new com.soywiz.krypto.a(key);
        int[] iArrI = H6.i(bArr);
        int length4 = iArrI.length;
        byte[] bArr2 = new byte[16];
        if (iv != null) {
            C4930v.d(0, 0, iv.length < 16 ? iv.length : 16, iv, bArr2);
        }
        int[] iArrI2 = H6.i(bArr2);
        if (iArrI.length % 4 != 0) {
            throw new IllegalArgumentException(Intrinsics.k(bVar2, "Data is not multiple of 16, and padding was set to "));
        }
        int i = iArrI2[0];
        int i2 = iArrI2[1];
        int i3 = iArrI2[2];
        int i4 = iArrI2[3];
        h hVarG = l.g(4, l.h(0, length4));
        int i5 = hVarG.a;
        int i6 = hVarG.b;
        int i7 = hVarG.c;
        if ((i7 <= 0 || i5 > i6) && (i7 >= 0 || i6 > i5)) {
            iArr = iArrI;
        } else {
            while (true) {
                int i8 = i5;
                i5 = i8 + i7;
                iArrI[i8] = i ^ iArrI[i8];
                int i9 = i8 + 1;
                iArrI[i9] = i2 ^ iArrI[i9];
                int i10 = i8 + 2;
                iArrI[i10] = i3 ^ iArrI[i10];
                int i11 = i8 + 3;
                iArrI[i11] = i4 ^ iArrI[i11];
                com.soywiz.krypto.a aVar3 = aVar2;
                iArr = iArrI;
                aVar3.a(iArr, i8, aVar2.e, com.soywiz.krypto.a.i, com.soywiz.krypto.a.j, com.soywiz.krypto.a.k, com.soywiz.krypto.a.l, com.soywiz.krypto.a.g);
                int i12 = iArr[i8];
                int i13 = iArr[i9];
                int i14 = iArr[i10];
                int i15 = iArr[i11];
                if (i8 == i6) {
                    break;
                }
                i2 = i13;
                i4 = i15;
                i3 = i14;
                aVar2 = aVar3;
                i = i12;
                iArrI = iArr;
            }
        }
        return H6.h(iArr);
    }
}
