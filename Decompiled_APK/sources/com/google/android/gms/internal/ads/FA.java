package com.google.android.gms.internal.ads;

import java.util.Locale;

/* loaded from: classes2.dex */
public final class FA extends HA {
    public final byte[] e;
    public final int f;
    public int g;

    public FA(int i, byte[] bArr) {
        int length = bArr.length;
        if (((length - i) | i) < 0) {
            Locale locale = Locale.US;
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Array range is invalid. Buffer.length=", length, ", offset=0, length=", i));
        }
        this.e = bArr;
        this.g = 0;
        this.f = i;
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void F(byte b) throws zzgxu {
        IndexOutOfBoundsException indexOutOfBoundsException;
        int i = this.g;
        try {
            int i2 = i + 1;
            try {
                this.e[i] = b;
                this.g = i2;
            } catch (IndexOutOfBoundsException e) {
                indexOutOfBoundsException = e;
                i = i2;
                throw new zzgxu(i, this.f, 1, indexOutOfBoundsException);
            }
        } catch (IndexOutOfBoundsException e2) {
            indexOutOfBoundsException = e2;
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void G(int i, boolean z) throws zzgxu {
        S(i << 3);
        F(z ? (byte) 1 : (byte) 0);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void H(int i, BA ba) throws zzgxu {
        S((i << 3) | 2);
        S(ba.g());
        ba.s(this);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void I(int i, int i2) throws zzgxu {
        S((i << 3) | 5);
        J(i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void J(int i) throws zzgxu {
        int i2 = this.g;
        try {
            byte[] bArr = this.e;
            bArr[i2] = (byte) i;
            bArr[i2 + 1] = (byte) (i >> 8);
            bArr[i2 + 2] = (byte) (i >> 16);
            bArr[i2 + 3] = (byte) (i >> 24);
            this.g = i2 + 4;
        } catch (IndexOutOfBoundsException e) {
            throw new zzgxu(i2, this.f, 4, e);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void K(int i, long j) throws zzgxu {
        S((i << 3) | 1);
        L(j);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void L(long j) throws zzgxu {
        int i = this.g;
        try {
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
        } catch (IndexOutOfBoundsException e) {
            throw new zzgxu(i, this.f, 8, e);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void M(int i, int i2) throws zzgxu {
        S(i << 3);
        N(i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void N(int i) throws zzgxu {
        if (i >= 0) {
            S(i);
        } else {
            U(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void O(int i, AbstractC2647tA abstractC2647tA, InterfaceC2562rB interfaceC2562rB) throws zzgxu {
        S((i << 3) | 2);
        S(abstractC2647tA.a(interfaceC2562rB));
        interfaceC2562rB.e(abstractC2647tA, this.b);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void P(int i, String str) throws zzgxu {
        S((i << 3) | 2);
        int i2 = this.g;
        try {
            int iC = HA.C(str.length() * 3);
            int iC2 = HA.C(str.length());
            byte[] bArr = this.e;
            int i3 = this.f;
            if (iC2 != iC) {
                S(BB.c(str));
                int i4 = this.g;
                this.g = BB.b(str, bArr, i4, i3 - i4);
            } else {
                int i5 = i2 + iC2;
                this.g = i5;
                int iB = BB.b(str, bArr, i5, i3 - i5);
                this.g = i2;
                S((iB - i2) - iC2);
                this.g = iB;
            }
        } catch (AB e) {
            this.g = i2;
            E(str, e);
        } catch (IndexOutOfBoundsException e2) {
            throw new zzgxu(e2);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void Q(int i, int i2) throws zzgxu {
        S((i << 3) | i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void R(int i, int i2) throws zzgxu {
        S(i << 3);
        S(i2);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void S(int i) throws zzgxu {
        int i2;
        int i3 = this.g;
        while (true) {
            int i4 = i & (-128);
            byte[] bArr = this.e;
            if (i4 == 0) {
                i2 = i3 + 1;
                bArr[i3] = (byte) i;
                this.g = i2;
                return;
            } else {
                i2 = i3 + 1;
                try {
                    bArr[i3] = (byte) (i | 128);
                    i >>>= 7;
                    i3 = i2;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzgxu(i2, this.f, 1, e);
                }
            }
            throw new zzgxu(i2, this.f, 1, e);
        }
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void T(int i, long j) throws zzgxu {
        S(i << 3);
        U(j);
    }

    @Override // com.google.android.gms.internal.ads.HA
    public final void U(long j) throws zzgxu {
        int i;
        int i2 = this.g;
        byte[] bArr = this.e;
        boolean z = HA.d;
        int i3 = this.f;
        if (!z || i3 - i2 < 10) {
            long j2 = j;
            while ((j2 & (-128)) != 0) {
                i = i2 + 1;
                try {
                    bArr[i2] = (byte) (((int) j2) | 128);
                    j2 >>>= 7;
                    i2 = i;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzgxu(i, i3, 1, e);
                }
            }
            i = i2 + 1;
            bArr[i2] = (byte) j2;
        } else {
            long j3 = j;
            while ((j3 & (-128)) != 0) {
                AbstractC2906zB.k(bArr, (byte) (((int) j3) | 128), i2);
                j3 >>>= 7;
                i2++;
            }
            i = i2 + 1;
            AbstractC2906zB.k(bArr, (byte) j3, i2);
        }
        this.g = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2457os
    public final void h(int i, byte[] bArr, int i2) throws zzgxu {
        try {
            System.arraycopy(bArr, i, this.e, this.g, i2);
            this.g += i2;
        } catch (IndexOutOfBoundsException e) {
            throw new zzgxu(this.g, this.f, i2, e);
        }
    }
}
