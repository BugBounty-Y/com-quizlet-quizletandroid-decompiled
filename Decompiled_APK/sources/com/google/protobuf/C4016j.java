package com.google.protobuf;

/* renamed from: com.google.protobuf.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4016j extends AbstractC4018l {
    public final byte[] f;
    public final int g;
    public int h;

    public C4016j(int i, byte[] bArr) {
        if (((bArr.length - i) | i) < 0) {
            throw new IllegalArgumentException(String.format("Array range is invalid. Buffer.length=%d, offset=%d, length=%d", Integer.valueOf(bArr.length), 0, Integer.valueOf(i)));
        }
        this.f = bArr;
        this.h = 0;
        this.g = i;
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void A(int i, String str) throws CodedOutputStream$OutOfSpaceException {
        C(i, 2);
        B(str);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void B(String str) throws CodedOutputStream$OutOfSpaceException {
        int i = this.h;
        try {
            int iK = AbstractC4018l.k(str.length() * 3);
            int iK2 = AbstractC4018l.k(str.length());
            byte[] bArr = this.f;
            if (iK2 != iK) {
                E(w0.b(str));
                this.h = w0.a.b(str, bArr, this.h, H());
                return;
            }
            int i2 = i + iK2;
            this.h = i2;
            int iB = w0.a.b(str, bArr, i2, H());
            this.h = i;
            E((iB - i) - iK2);
            this.h = iB;
        } catch (v0 e) {
            this.h = i;
            m(str, e);
        } catch (IndexOutOfBoundsException e2) {
            throw new CodedOutputStream$OutOfSpaceException(e2);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void C(int i, int i2) throws CodedOutputStream$OutOfSpaceException {
        E((i << 3) | i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void D(int i, int i2) throws CodedOutputStream$OutOfSpaceException {
        C(i, 0);
        E(i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void E(int i) throws CodedOutputStream$OutOfSpaceException {
        while (true) {
            int i2 = i & (-128);
            byte[] bArr = this.f;
            if (i2 == 0) {
                int i3 = this.h;
                this.h = i3 + 1;
                bArr[i3] = (byte) i;
                return;
            } else {
                try {
                    int i4 = this.h;
                    this.h = i4 + 1;
                    bArr[i4] = (byte) ((i | 128) & 255);
                    i >>>= 7;
                } catch (IndexOutOfBoundsException e) {
                    throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
                }
            }
            throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void F(int i, long j) throws CodedOutputStream$OutOfSpaceException {
        C(i, 0);
        G(j);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void G(long j) throws CodedOutputStream$OutOfSpaceException {
        byte[] bArr = this.f;
        if (!AbstractC4018l.e || H() < 10) {
            while ((j & (-128)) != 0) {
                try {
                    int i = this.h;
                    this.h = i + 1;
                    bArr[i] = (byte) ((((int) j) | 128) & 255);
                    j >>>= 7;
                } catch (IndexOutOfBoundsException e) {
                    throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
                }
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

    public final int H() {
        return this.g - this.h;
    }

    public final void I(byte[] bArr, int i, int i2) throws CodedOutputStream$OutOfSpaceException {
        try {
            System.arraycopy(bArr, i, this.f, this.h, i2);
            this.h += i2;
        } catch (IndexOutOfBoundsException e) {
            throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), Integer.valueOf(i2)), e);
        }
    }

    @Override // com.google.protobuf.h0
    public final void f(int i, byte[] bArr, int i2) throws CodedOutputStream$OutOfSpaceException {
        I(bArr, i, i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void n(byte b) throws CodedOutputStream$OutOfSpaceException {
        try {
            byte[] bArr = this.f;
            int i = this.h;
            this.h = i + 1;
            bArr[i] = b;
        } catch (IndexOutOfBoundsException e) {
            throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void o(int i, boolean z) throws CodedOutputStream$OutOfSpaceException {
        C(i, 0);
        n(z ? (byte) 1 : (byte) 0);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void p(int i, byte[] bArr) throws CodedOutputStream$OutOfSpaceException {
        E(i);
        I(bArr, 0, i);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void q(int i, C4012f c4012f) throws CodedOutputStream$OutOfSpaceException {
        C(i, 2);
        r(c4012f);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void r(C4012f c4012f) throws CodedOutputStream$OutOfSpaceException {
        E(c4012f.size());
        f(c4012f.e(), c4012f.b, c4012f.size());
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void s(int i, int i2) throws CodedOutputStream$OutOfSpaceException {
        C(i, 5);
        t(i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void t(int i) throws CodedOutputStream$OutOfSpaceException {
        try {
            byte[] bArr = this.f;
            int i2 = this.h;
            int i3 = i2 + 1;
            this.h = i3;
            bArr[i2] = (byte) (i & 255);
            int i4 = i2 + 2;
            this.h = i4;
            bArr[i3] = (byte) ((i >> 8) & 255);
            int i5 = i2 + 3;
            this.h = i5;
            bArr[i4] = (byte) ((i >> 16) & 255);
            this.h = i2 + 4;
            bArr[i5] = (byte) ((i >> 24) & 255);
        } catch (IndexOutOfBoundsException e) {
            throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void u(int i, long j) throws CodedOutputStream$OutOfSpaceException {
        C(i, 1);
        v(j);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void v(long j) throws CodedOutputStream$OutOfSpaceException {
        try {
            byte[] bArr = this.f;
            int i = this.h;
            int i2 = i + 1;
            this.h = i2;
            bArr[i] = (byte) (((int) j) & 255);
            int i3 = i + 2;
            this.h = i3;
            bArr[i2] = (byte) (((int) (j >> 8)) & 255);
            int i4 = i + 3;
            this.h = i4;
            bArr[i3] = (byte) (((int) (j >> 16)) & 255);
            int i5 = i + 4;
            this.h = i5;
            bArr[i4] = (byte) (((int) (j >> 24)) & 255);
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
        } catch (IndexOutOfBoundsException e) {
            throw new CodedOutputStream$OutOfSpaceException(String.format("Pos: %d, limit: %d, len: %d", Integer.valueOf(this.h), Integer.valueOf(this.g), 1), e);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void w(int i, int i2) throws CodedOutputStream$OutOfSpaceException {
        C(i, 0);
        x(i2);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void x(int i) throws CodedOutputStream$OutOfSpaceException {
        if (i >= 0) {
            E(i);
        } else {
            G(i);
        }
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void y(int i, AbstractC4004a abstractC4004a, InterfaceC4009c0 interfaceC4009c0) throws CodedOutputStream$OutOfSpaceException {
        C(i, 2);
        E(abstractC4004a.h(interfaceC4009c0));
        interfaceC4009c0.e(abstractC4004a, this.c);
    }

    @Override // com.google.protobuf.AbstractC4018l
    public final void z(AbstractC4004a abstractC4004a) throws CodedOutputStream$OutOfSpaceException {
        E(((AbstractC4027v) abstractC4004a).h(null));
        abstractC4004a.i(this);
    }
}
