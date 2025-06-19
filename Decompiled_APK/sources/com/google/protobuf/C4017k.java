package com.google.protobuf;

import java.io.IOException;
import java.io.OutputStream;

/* renamed from: com.google.protobuf.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4017k extends AbstractC4018l {
    public final byte[] f;
    public final int g;
    public int h;
    public final OutputStream i;

    public C4017k(OutputStream outputStream, int i) {
        if (i < 0) {
            throw new IllegalArgumentException("bufferSize must be >= 0");
        }
        int iMax = Math.max(i, 20);
        this.f = new byte[iMax];
        this.g = iMax;
        if (outputStream == null) {
            throw new NullPointerException("out");
        }
        this.i = outputStream;
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void A(int i, String str) throws IOException {
        C(i, 2);
        B(str);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void B(String str) throws IOException {
        try {
            int length = str.length() * 3;
            int iK = AbstractC4018l.k(length);
            int i = iK + length;
            int i2 = this.g;
            if (i > i2) {
                byte[] bArr = new byte[length];
                int iB = w0.a.b(str, bArr, 0, length);
                E(iB);
                O(bArr, 0, iB);
                return;
            }
            if (i > i2 - this.h) {
                M();
            }
            int iK2 = AbstractC4018l.k(str.length());
            int i3 = this.h;
            byte[] bArr2 = this.f;
            try {
                try {
                    if (iK2 == iK) {
                        int i4 = i3 + iK2;
                        this.h = i4;
                        int iB2 = w0.a.b(str, bArr2, i4, i2 - i4);
                        this.h = i3;
                        K((iB2 - i3) - iK2);
                        this.h = iB2;
                    } else {
                        int iB3 = w0.b(str);
                        K(iB3);
                        this.h = w0.a.b(str, bArr2, this.h, iB3);
                    }
                } catch (v0 e) {
                    this.h = i3;
                    throw e;
                }
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new CodedOutputStream$OutOfSpaceException(e2);
            }
        } catch (v0 e3) {
            m(str, e3);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void C(int i, int i2) {
        E((i << 3) | i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void D(int i, int i2) {
        N(20);
        J(i, 0);
        K(i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void E(int i) {
        N(5);
        K(i);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void F(int i, long j) {
        N(20);
        J(i, 0);
        L(j);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void G(long j) {
        N(10);
        L(j);
    }

    public final void H(int i) {
        int i2 = this.h;
        int i3 = i2 + 1;
        this.h = i3;
        byte[] bArr = this.f;
        bArr[i2] = (byte) (i & 255);
        int i4 = i2 + 2;
        this.h = i4;
        bArr[i3] = (byte) ((i >> 8) & 255);
        int i5 = i2 + 3;
        this.h = i5;
        bArr[i4] = (byte) ((i >> 16) & 255);
        this.h = i2 + 4;
        bArr[i5] = (byte) ((i >> 24) & 255);
    }

    public final void I(long j) {
        int i = this.h;
        int i2 = i + 1;
        this.h = i2;
        byte[] bArr = this.f;
        bArr[i] = (byte) (j & 255);
        int i3 = i + 2;
        this.h = i3;
        bArr[i2] = (byte) ((j >> 8) & 255);
        int i4 = i + 3;
        this.h = i4;
        bArr[i3] = (byte) ((j >> 16) & 255);
        int i5 = i + 4;
        this.h = i5;
        bArr[i4] = (byte) (255 & (j >> 24));
        int i6 = i + 5;
        this.h = i6;
        bArr[i5] = (byte) (((int) (j >> 32)) & 255);
        int i7 = i + 6;
        this.h = i7;
        bArr[i6] = (byte) (((int) (j >> 40)) & 255);
        int i8 = i + 7;
        this.h = i8;
        bArr[i7] = (byte) (((int) (j >> 48)) & 255);
        this.h = i + 8;
        bArr[i8] = (byte) (((int) (j >> 56)) & 255);
    }

    public final void J(int i, int i2) {
        K((i << 3) | i2);
    }

    public final void K(int i) {
        boolean z = AbstractC4018l.e;
        byte[] bArr = this.f;
        if (!z) {
            while ((i & (-128)) != 0) {
                int i2 = this.h;
                this.h = i2 + 1;
                bArr[i2] = (byte) ((i | 128) & 255);
                i >>>= 7;
            }
            int i3 = this.h;
            this.h = i3 + 1;
            bArr[i3] = (byte) i;
            return;
        }
        while ((i & (-128)) != 0) {
            int i4 = this.h;
            this.h = i4 + 1;
            t0.k(bArr, (byte) ((i | 128) & 255), i4);
            i >>>= 7;
        }
        int i5 = this.h;
        this.h = i5 + 1;
        t0.k(bArr, (byte) i, i5);
    }

    public final void L(long j) {
        boolean z = AbstractC4018l.e;
        byte[] bArr = this.f;
        if (!z) {
            while ((j & (-128)) != 0) {
                int i = this.h;
                this.h = i + 1;
                bArr[i] = (byte) ((((int) j) | 128) & 255);
                j >>>= 7;
            }
            int i2 = this.h;
            this.h = i2 + 1;
            bArr[i2] = (byte) j;
            return;
        }
        while ((j & (-128)) != 0) {
            int i3 = this.h;
            this.h = i3 + 1;
            t0.k(bArr, (byte) ((((int) j) | 128) & 255), i3);
            j >>>= 7;
        }
        int i4 = this.h;
        this.h = i4 + 1;
        t0.k(bArr, (byte) j, i4);
    }

    public final void M() {
        this.i.write(this.f, 0, this.h);
        this.h = 0;
    }

    public final void N(int i) {
        if (this.g - this.h < i) {
            M();
        }
    }

    public final void O(byte[] bArr, int i, int i2) throws IOException {
        int i3 = this.h;
        int i4 = this.g;
        int i5 = i4 - i3;
        byte[] bArr2 = this.f;
        if (i5 >= i2) {
            System.arraycopy(bArr, i, bArr2, i3, i2);
            this.h += i2;
            return;
        }
        System.arraycopy(bArr, i, bArr2, i3, i5);
        int i6 = i + i5;
        int i7 = i2 - i5;
        this.h = i4;
        M();
        if (i7 > i4) {
            this.i.write(bArr, i6, i7);
        } else {
            System.arraycopy(bArr, i6, bArr2, 0, i7);
            this.h = i7;
        }
    }

    @Override // com.google.protobuf.h0
    public final void f(int i, byte[] bArr, int i2) throws IOException {
        O(bArr, i, i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void n(byte b) {
        if (this.h == this.g) {
            M();
        }
        int i = this.h;
        this.h = i + 1;
        this.f[i] = b;
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void o(int i, boolean z) {
        N(11);
        J(i, 0);
        byte b = z ? (byte) 1 : (byte) 0;
        int i2 = this.h;
        this.h = i2 + 1;
        this.f[i2] = b;
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void p(int i, byte[] bArr) throws IOException {
        E(i);
        O(bArr, 0, i);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void q(int i, C4012f c4012f) {
        C(i, 2);
        r(c4012f);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void r(C4012f c4012f) {
        E(c4012f.size());
        f(c4012f.e(), c4012f.b, c4012f.size());
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void s(int i, int i2) {
        N(14);
        J(i, 5);
        H(i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void t(int i) {
        N(4);
        H(i);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void u(int i, long j) {
        N(18);
        J(i, 1);
        I(j);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void v(long j) {
        N(8);
        I(j);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void w(int i, int i2) {
        N(20);
        J(i, 0);
        if (i2 >= 0) {
            K(i2);
        } else {
            L(i2);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void x(int i) {
        if (i >= 0) {
            E(i);
        } else {
            G(i);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void y(int i, AbstractC4004a abstractC4004a, InterfaceC4009c0 interfaceC4009c0) {
        C(i, 2);
        E(abstractC4004a.h(interfaceC4009c0));
        interfaceC4009c0.e(abstractC4004a, this.c);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void z(AbstractC4004a abstractC4004a) {
        E(((AbstractC4027v) abstractC4004a).h(null));
        abstractC4004a.i(this);
    }
}
