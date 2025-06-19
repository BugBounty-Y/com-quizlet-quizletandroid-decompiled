package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.uE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2694uE extends AbstractC1754Pf {
    public int i;
    public boolean j;
    public int k;
    public long l;
    public int m;
    public byte[] n;
    public int o;
    public int p;
    public byte[] q;

    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final void c(ByteBuffer byteBuffer) {
        int iLimit;
        int i;
        int iPosition;
        while (byteBuffer.hasRemaining() && !this.g.hasRemaining()) {
            if (this.k != 0) {
                AbstractC1795We.L(this.o < this.n.length);
                int iLimit2 = byteBuffer.limit();
                int iPosition2 = byteBuffer.position() + 1;
                while (true) {
                    if (iPosition2 >= byteBuffer.limit()) {
                        iLimit = byteBuffer.limit();
                        break;
                    }
                    if (Math.abs((byteBuffer.get(iPosition2) << 8) | (byteBuffer.get(iPosition2 - 1) & 255)) > 1024) {
                        int i2 = this.i;
                        iLimit = (iPosition2 / i2) * i2;
                        break;
                    }
                    iPosition2 += 2;
                }
                int iPosition3 = iLimit - byteBuffer.position();
                int i3 = this.o;
                int i4 = this.p;
                int i5 = i3 + i4;
                int length = this.n.length;
                if (i5 < length) {
                    i = length - i5;
                } else {
                    i5 = i4 - (length - i3);
                    i = i3 - i5;
                }
                int iMin = Math.min(iPosition3, i);
                byteBuffer.limit(byteBuffer.position() + iMin);
                byteBuffer.get(this.n, i5, iMin);
                int i6 = this.p + iMin;
                this.p = i6;
                AbstractC1795We.L(i6 <= this.n.length);
                boolean z = iLimit < iLimit2 && iPosition3 < i;
                n(z);
                if (z) {
                    this.k = 0;
                    this.m = 0;
                }
                byteBuffer.limit(iLimit2);
            } else {
                int iLimit3 = byteBuffer.limit();
                byteBuffer.limit(Math.min(iLimit3, byteBuffer.position() + this.n.length));
                int iLimit4 = byteBuffer.limit() - 1;
                while (true) {
                    if (iLimit4 < byteBuffer.position()) {
                        iPosition = byteBuffer.position();
                        break;
                    }
                    if (Math.abs((byteBuffer.get(iLimit4) << 8) | (byteBuffer.get(iLimit4 - 1) & 255)) > 1024) {
                        int i7 = this.i;
                        iPosition = ((iLimit4 / i7) * i7) + i7;
                        break;
                    }
                    iLimit4 -= 2;
                }
                if (iPosition == byteBuffer.position()) {
                    this.k = 1;
                } else {
                    byteBuffer.limit(Math.min(iPosition, byteBuffer.capacity()));
                    e(byteBuffer.remaining()).put(byteBuffer).flip();
                }
                byteBuffer.limit(iLimit3);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final C2229jf d(C2229jf c2229jf) throws zzcm {
        if (c2229jf.c == 2) {
            return c2229jf.a == -1 ? C2229jf.e : c2229jf;
        }
        throw new zzcm("Unhandled input format:", c2229jf);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf, com.google.android.gms.internal.ads.InterfaceC1688Ef
    public final boolean h() {
        return super.h() && this.j;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void i() {
        if (h()) {
            int i = this.b.b;
            int i2 = i + i;
            this.i = i2;
            int i3 = ((((int) ((100000 * r0.a) / 1000000)) / 2) / i2) * i2;
            int i4 = i3 + i3;
            if (this.n.length != i4) {
                this.n = new byte[i4];
                this.q = new byte[i4];
            }
        }
        this.k = 0;
        this.l = 0L;
        this.m = 0;
        this.o = 0;
        this.p = 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void k() {
        if (this.p > 0) {
            n(true);
            this.m = 0;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final void l() {
        this.j = false;
        byte[] bArr = Yo.b;
        this.n = bArr;
        this.q = bArr;
    }

    public final int m(int i) {
        int length = ((((int) ((2000000 * this.b.a) / 1000000)) - this.m) * this.i) - (this.n.length >> 1);
        AbstractC1795We.L(length >= 0);
        int iMin = (int) Math.min((i * 0.2f) + 0.5f, length);
        int i2 = this.i;
        return (iMin / i2) * i2;
    }

    public final void n(boolean z) {
        int i;
        int length;
        int i2 = this.p;
        int length2 = this.n.length;
        if (i2 != length2) {
            if (!z) {
                return;
            } else {
                z = true;
            }
        }
        if (this.m == 0) {
            if (z) {
                o(i2, 3);
                length = i2;
            } else {
                AbstractC1795We.L(i2 >= (length2 >> 1));
                length = this.n.length >> 1;
                o(length, 0);
            }
            i = length;
        } else {
            int i3 = length2 >> 1;
            int i4 = i2 - i3;
            if (z) {
                int iM = m(i4) + (this.n.length >> 1);
                o(iM, 2);
                int i5 = i3 + i4;
                i = iM;
                length = i5;
            } else {
                int iM2 = m(i4);
                o(iM2, 1);
                i = iM2;
                length = i4;
            }
        }
        boolean z2 = length % this.i == 0;
        String strF = android.support.v4.media.session.a.f(length, "bytesConsumed is not aligned to frame size: %s");
        if (!z2) {
            throw new IllegalStateException(String.valueOf(strF));
        }
        AbstractC1795We.L(i2 >= i);
        this.p -= length;
        int i6 = this.o + length;
        this.o = i6;
        this.o = i6 % this.n.length;
        this.m = (i / this.i) + this.m;
        this.l += (length - i) / r2;
    }

    public final void o(int i, int i2) {
        int i3;
        if (i == 0) {
            return;
        }
        AbstractC1795We.B(this.p >= i);
        if (i2 == 2) {
            int i4 = this.o;
            int i5 = this.p;
            int i6 = i4 + i5;
            byte[] bArr = this.n;
            int length = bArr.length;
            if (i6 <= length) {
                System.arraycopy(bArr, i6 - i, this.q, 0, i);
            } else {
                int i7 = i5 - (length - i4);
                if (i7 >= i) {
                    System.arraycopy(bArr, i7 - i, this.q, 0, i);
                } else {
                    int i8 = i - i7;
                    System.arraycopy(bArr, length - i8, this.q, 0, i8);
                    System.arraycopy(this.n, 0, this.q, i8, i7);
                }
            }
        } else {
            int i9 = this.o;
            int i10 = i9 + i;
            byte[] bArr2 = this.n;
            int length2 = bArr2.length;
            if (i10 <= length2) {
                System.arraycopy(bArr2, i9, this.q, 0, i);
            } else {
                int i11 = length2 - i9;
                System.arraycopy(bArr2, i9, this.q, 0, i11);
                System.arraycopy(this.n, 0, this.q, i11, i - i11);
            }
        }
        AbstractC1795We.G(i % this.i == 0, "sizeToOutput is not aligned to frame size: " + i);
        AbstractC1795We.L(this.o < this.n.length);
        byte[] bArr3 = this.q;
        AbstractC1795We.G(i % this.i == 0, android.support.v4.media.session.a.f(i, "byteOutput size is not aligned to frame size "));
        if (i2 != 3) {
            for (int i12 = 0; i12 < i; i12 += 2) {
                int i13 = i12 + 1;
                int i14 = (bArr3[i13] << 8) | (bArr3[i12] & 255);
                if (i2 == 0) {
                    i3 = ((((i12 * 1000) / (i - 1)) * (-90)) / 1000) + 100;
                } else {
                    i3 = 10;
                    if (i2 == 2) {
                        i3 = 10 + (((90000 * i12) / (i - 1)) / 1000);
                    }
                }
                int i15 = (i14 * i3) / 100;
                if (i15 >= 32767) {
                    bArr3[i12] = -1;
                    bArr3[i13] = Byte.MAX_VALUE;
                } else if (i15 <= -32768) {
                    bArr3[i12] = 0;
                    bArr3[i13] = Byte.MIN_VALUE;
                } else {
                    bArr3[i12] = (byte) (i15 & 255);
                    bArr3[i13] = (byte) (i15 >> 8);
                }
            }
        }
        e(i).put(bArr3, 0, i).flip();
    }
}
