package com.google.android.gms.internal.ads;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class GA extends HA {
    public final byte[] e;
    public final int f;
    public int g;
    public final ByteArrayOutputStream h;

    public GA(ByteArrayOutputStream byteArrayOutputStream, int i) {
        if (i < 0) {
            throw new IllegalArgumentException("bufferSize must be >= 0");
        }
        int iMax = Math.max(i, 20);
        this.e = new byte[iMax];
        this.f = iMax;
        this.h = byteArrayOutputStream;
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void F(byte b) throws IOException {
        if (this.g == this.f) {
            V();
        }
        int i = this.g;
        this.e[i] = b;
        this.g = i + 1;
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void G(int i, boolean z) throws IOException {
        W(11);
        Z(i << 3);
        int i2 = this.g;
        this.e[i2] = z ? (byte) 1 : (byte) 0;
        this.g = i2 + 1;
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void H(int i, BA ba) throws IOException {
        S((i << 3) | 2);
        S(ba.g());
        ba.s(this);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void I(int i, int i2) throws IOException {
        W(14);
        Z((i << 3) | 5);
        X(i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void J(int i) throws IOException {
        W(4);
        X(i);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void K(int i, long j) throws IOException {
        W(18);
        Z((i << 3) | 1);
        Y(j);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void L(long j) throws IOException {
        W(8);
        Y(j);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void M(int i, int i2) throws IOException {
        W(20);
        Z(i << 3);
        if (i2 >= 0) {
            Z(i2);
        } else {
            a0(i2);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void N(int i) throws IOException {
        if (i >= 0) {
            S(i);
        } else {
            U(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void O(int i, AbstractC2647tA abstractC2647tA, InterfaceC2562rB interfaceC2562rB) throws IOException {
        S((i << 3) | 2);
        S(abstractC2647tA.a(interfaceC2562rB));
        interfaceC2562rB.e(abstractC2647tA, this.b);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void P(int i, String str) throws IOException {
        S((i << 3) | 2);
        try {
            int length = str.length() * 3;
            int iC = HA.C(length);
            int i2 = iC + length;
            int i3 = this.f;
            if (i2 > i3) {
                byte[] bArr = new byte[length];
                int iB = BB.b(str, bArr, 0, length);
                S(iB);
                b0(0, bArr, iB);
                return;
            }
            if (i2 > i3 - this.g) {
                V();
            }
            int iC2 = HA.C(str.length());
            int i4 = this.g;
            byte[] bArr2 = this.e;
            try {
                if (iC2 == iC) {
                    int i5 = i4 + iC2;
                    this.g = i5;
                    int iB2 = BB.b(str, bArr2, i5, i3 - i5);
                    this.g = i4;
                    Z((iB2 - i4) - iC2);
                    this.g = iB2;
                } else {
                    int iC3 = BB.c(str);
                    Z(iC3);
                    this.g = BB.b(str, bArr2, this.g, iC3);
                }
            } catch (AB e) {
                this.g = i4;
                throw e;
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new zzgxu(e2);
            }
        } catch (AB e3) {
            E(str, e3);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void Q(int i, int i2) throws IOException {
        S((i << 3) | i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void R(int i, int i2) throws IOException {
        W(20);
        Z(i << 3);
        Z(i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void S(int i) throws IOException {
        W(5);
        Z(i);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void T(int i, long j) throws IOException {
        W(20);
        Z(i << 3);
        a0(j);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void U(long j) throws IOException {
        W(10);
        a0(j);
    }

    public final void V() throws IOException {
        this.h.write(this.e, 0, this.g);
        this.g = 0;
    }

    public final void W(int i) throws IOException {
        if (this.f - this.g < i) {
            V();
        }
    }

    public final void X(int i) {
        int i2 = this.g;
        byte[] bArr = this.e;
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >> 8);
        bArr[i2 + 2] = (byte) (i >> 16);
        bArr[i2 + 3] = (byte) (i >> 24);
        this.g = i2 + 4;
    }

    public final void Y(long j) {
        int i = this.g;
        byte[] bArr = this.e;
        bArr[i] = (byte) j;
        bArr[i + 1] = (byte) (j >> 8);
        bArr[i + 2] = (byte) (j >> 16);
        bArr[i + 3] = (byte) (j >> 24);
        bArr[i + 4] = (byte) (j >> 32);
        bArr[i + 5] = (byte) (j >> 40);
        bArr[i + 6] = (byte) (j >> 48);
        bArr[i + 7] = (byte) (j >> 56);
        this.g = i + 8;
    }

    public final void Z(int i) {
        boolean z = HA.d;
        byte[] bArr = this.e;
        if (!z) {
            while ((i & (-128)) != 0) {
                int i2 = this.g;
                this.g = i2 + 1;
                bArr[i2] = (byte) (i | 128);
                i >>>= 7;
            }
            int i3 = this.g;
            this.g = i3 + 1;
            bArr[i3] = (byte) i;
            return;
        }
        while ((i & (-128)) != 0) {
            int i4 = this.g;
            this.g = i4 + 1;
            AbstractC2906zB.k(bArr, (byte) (i | 128), i4);
            i >>>= 7;
        }
        int i5 = this.g;
        this.g = i5 + 1;
        AbstractC2906zB.k(bArr, (byte) i, i5);
    }

    public final void a0(long j) {
        boolean z = HA.d;
        byte[] bArr = this.e;
        if (z) {
            while (true) {
                int i = (int) j;
                if ((j & (-128)) == 0) {
                    int i2 = this.g;
                    this.g = i2 + 1;
                    AbstractC2906zB.k(bArr, (byte) i, i2);
                    return;
                }
                int i3 = this.g;
                this.g = i3 + 1;
                AbstractC2906zB.k(bArr, (byte) (i | 128), i3);
                j >>>= 7;
            }
        } else {
            while (true) {
                int i4 = (int) j;
                if ((j & (-128)) == 0) {
                    int i5 = this.g;
                    this.g = i5 + 1;
                    bArr[i5] = (byte) i4;
                    return;
                } else {
                    int i6 = this.g;
                    this.g = i6 + 1;
                    bArr[i6] = (byte) (i4 | 128);
                    j >>>= 7;
                }
            }
        }
    }

    public final void b0(int i, byte[] bArr, int i2) throws IOException {
        int i3 = this.g;
        int i4 = this.f;
        int i5 = i4 - i3;
        byte[] bArr2 = this.e;
        if (i5 >= i2) {
            System.arraycopy(bArr, i, bArr2, i3, i2);
            this.g += i2;
            return;
        }
        System.arraycopy(bArr, i, bArr2, i3, i5);
        int i6 = i + i5;
        this.g = i4;
        V();
        int i7 = i2 - i5;
        if (i7 > i4) {
            this.h.write(bArr, i6, i7);
        } else {
            System.arraycopy(bArr, i6, bArr2, 0, i7);
            this.g = i7;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void h(int i, byte[] bArr, int i2) throws IOException {
        b0(i, bArr, i2);
    }
}
