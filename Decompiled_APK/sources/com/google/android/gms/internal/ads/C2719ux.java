package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import java.security.InvalidKeyException;

/* renamed from: com.google.android.gms.internal.ads.ux, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2719ux extends AbstractC1047f0 {
    public final /* synthetic */ int c;

    public C2719ux(int i, byte[] bArr, int i2) throws InvalidKeyException {
        this.c = i2;
        if (bArr.length != 32) {
            throw new InvalidKeyException("The key length in bytes must be 32.");
        }
        this.b = AbstractC2676tx.d(bArr);
        this.a = i;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int M() {
        switch (this.c) {
            case 0:
                return 12;
            default:
                return 24;
        }
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int[] O(int[] iArr, int i) {
        switch (this.c) {
            case 0:
                int length = iArr.length;
                if (length != 3) {
                    throw new IllegalArgumentException(String.format("ChaCha20 uses 96-bit nonces, but got a %d-bit nonce", Integer.valueOf(length * 32)));
                }
                int[] iArr2 = new int[16];
                int[] iArr3 = (int[]) this.b;
                int[] iArr4 = AbstractC2676tx.a;
                int length2 = iArr4.length;
                System.arraycopy(iArr4, 0, iArr2, 0, length2);
                System.arraycopy(iArr3, 0, iArr2, length2, 8);
                iArr2[12] = i;
                System.arraycopy(iArr, 0, iArr2, 13, 3);
                return iArr2;
            default:
                int length3 = iArr.length;
                if (length3 != 6) {
                    throw new IllegalArgumentException(String.format("XChaCha20 uses 192-bit nonces, but got a %d-bit nonce", Integer.valueOf(length3 * 32)));
                }
                int[] iArr5 = new int[16];
                int[] iArrC = AbstractC2676tx.c((int[]) this.b, iArr);
                int[] iArr6 = AbstractC2676tx.a;
                int length4 = iArr6.length;
                System.arraycopy(iArr6, 0, iArr5, 0, length4);
                System.arraycopy(iArrC, 0, iArr5, length4, 8);
                iArr5[12] = i;
                iArr5[13] = 0;
                iArr5[14] = iArr[4];
                iArr5[15] = iArr[5];
                return iArr5;
        }
    }
}
