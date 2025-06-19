package com.google.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: com.google.protobuf.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4014h extends AbstractC1047f0 {
    public final InputStream c;
    public final byte[] d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public C4014h(InputStream inputStream) {
        C.a(inputStream, "input");
        this.c = inputStream;
        this.d = new byte[4096];
        this.e = 0;
        this.g = 0;
        this.i = 0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String A() throws IOException {
        int iO0 = o0();
        int i = this.g;
        int i2 = this.e;
        int i3 = i2 - i;
        byte[] bArrJ0 = this.d;
        if (iO0 <= i3 && iO0 > 0) {
            this.g = i + iO0;
        } else {
            if (iO0 == 0) {
                return "";
            }
            i = 0;
            if (iO0 <= i2) {
                s0(iO0);
                this.g = iO0;
            } else {
                bArrJ0 = j0(iO0);
            }
        }
        return w0.a.a(i, bArrJ0, iO0);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int B() throws InvalidProtocolBufferException {
        if (c()) {
            this.h = 0;
            return 0;
        }
        int iO0 = o0();
        this.h = iO0;
        if ((iO0 >>> 3) != 0) {
            return iO0;
        }
        throw new InvalidProtocolBufferException("Protocol message contained an invalid tag (zero).");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int C() {
        return o0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long D() {
        return p0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean E(int i) throws InvalidProtocolBufferException {
        int iB;
        int i2 = i & 7;
        int i3 = 0;
        if (i2 == 0) {
            int i4 = this.e - this.g;
            byte[] bArr = this.d;
            if (i4 >= 10) {
                while (i3 < 10) {
                    int i5 = this.g;
                    this.g = i5 + 1;
                    if (bArr[i5] < 0) {
                        i3++;
                    }
                }
                throw InvalidProtocolBufferException.c();
            }
            while (i3 < 10) {
                if (this.g == this.e) {
                    s0(1);
                }
                int i6 = this.g;
                this.g = i6 + 1;
                if (bArr[i6] < 0) {
                    i3++;
                }
            }
            throw InvalidProtocolBufferException.c();
            return true;
        }
        if (i2 == 1) {
            t0(8);
            return true;
        }
        if (i2 == 2) {
            t0(o0());
            return true;
        }
        if (i2 != 3) {
            if (i2 == 4) {
                return false;
            }
            if (i2 != 5) {
                throw InvalidProtocolBufferException.b();
            }
            t0(4);
            return true;
        }
        do {
            iB = B();
            if (iB == 0) {
                break;
            }
        } while (E(iB));
        a(((i >>> 3) << 3) | 4);
        return true;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void a(int i) throws InvalidProtocolBufferException {
        if (this.h != i) {
            throw new InvalidProtocolBufferException("Protocol message end-group tag did not match expected tag.");
        }
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int b() {
        return this.i + this.g;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean c() {
        return this.g == this.e && !u0(1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void h(int i) {
        this.j = i;
        r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int i(int i) throws InvalidProtocolBufferException {
        if (i < 0) {
            throw InvalidProtocolBufferException.d();
        }
        int i2 = this.i + this.g + i;
        int i3 = this.j;
        if (i2 > i3) {
            throw InvalidProtocolBufferException.e();
        }
        this.j = i2;
        r0();
        return i3;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean j() {
        return p0() != 0;
    }

    public final byte[] j0(int i) throws IOException {
        byte[] bArrK0 = k0(i);
        if (bArrK0 != null) {
            return bArrK0;
        }
        int i2 = this.g;
        int i3 = this.e;
        int length = i3 - i2;
        this.i += i3;
        this.g = 0;
        this.e = 0;
        ArrayList arrayListL0 = l0(i - length);
        byte[] bArr = new byte[i];
        System.arraycopy(this.d, i2, bArr, 0, length);
        Iterator it2 = arrayListL0.iterator();
        while (it2.hasNext()) {
            byte[] bArr2 = (byte[]) it2.next();
            System.arraycopy(bArr2, 0, bArr, length, bArr2.length);
            length += bArr2.length;
        }
        return bArr;
    }

    public final byte[] k0(int i) throws IOException {
        if (i == 0) {
            return C.b;
        }
        if (i < 0) {
            throw InvalidProtocolBufferException.d();
        }
        int i2 = this.i;
        int i3 = this.g;
        int i4 = i2 + i3 + i;
        if (i4 - SubsamplingScaleImageView.TILE_SIZE_AUTO > 0) {
            throw new InvalidProtocolBufferException("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit.");
        }
        int i5 = this.j;
        if (i4 > i5) {
            t0((i5 - i2) - i3);
            throw InvalidProtocolBufferException.e();
        }
        int i6 = this.e - i3;
        int i7 = i - i6;
        InputStream inputStream = this.c;
        if (i7 >= 4096) {
            try {
                if (i7 > inputStream.available()) {
                    return null;
                }
            } catch (InvalidProtocolBufferException e) {
                e.a = true;
                throw e;
            }
        }
        byte[] bArr = new byte[i];
        System.arraycopy(this.d, this.g, bArr, 0, i6);
        this.i += this.e;
        this.g = 0;
        this.e = 0;
        while (i6 < i) {
            try {
                int i8 = inputStream.read(bArr, i6, i - i6);
                if (i8 == -1) {
                    throw InvalidProtocolBufferException.e();
                }
                this.i += i8;
                i6 += i8;
            } catch (InvalidProtocolBufferException e2) {
                e2.a = true;
                throw e2;
            }
        }
        return bArr;
    }

    public final ArrayList l0(int i) throws IOException {
        ArrayList arrayList = new ArrayList();
        while (i > 0) {
            int iMin = Math.min(i, 4096);
            byte[] bArr = new byte[iMin];
            int i2 = 0;
            while (i2 < iMin) {
                int i3 = this.c.read(bArr, i2, iMin - i2);
                if (i3 == -1) {
                    throw InvalidProtocolBufferException.e();
                }
                this.i += i3;
                i2 += i3;
            }
            i -= iMin;
            arrayList.add(bArr);
        }
        return arrayList;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final C4012f m() throws IOException {
        int iO0 = o0();
        int i = this.e;
        int i2 = this.g;
        int i3 = i - i2;
        byte[] bArr = this.d;
        if (iO0 <= i3 && iO0 > 0) {
            C4012f c4012fC = C4012f.c(i2, bArr, iO0);
            this.g += iO0;
            return c4012fC;
        }
        if (iO0 == 0) {
            return C4012f.c;
        }
        byte[] bArrK0 = k0(iO0);
        if (bArrK0 != null) {
            return C4012f.c(0, bArrK0, bArrK0.length);
        }
        int i4 = this.g;
        int i5 = this.e;
        int length = i5 - i4;
        this.i += i5;
        this.g = 0;
        this.e = 0;
        ArrayList arrayListL0 = l0(iO0 - length);
        byte[] bArr2 = new byte[iO0];
        System.arraycopy(bArr, i4, bArr2, 0, length);
        Iterator it2 = arrayListL0.iterator();
        while (it2.hasNext()) {
            byte[] bArr3 = (byte[]) it2.next();
            System.arraycopy(bArr3, 0, bArr2, length, bArr3.length);
            length += bArr3.length;
        }
        C4012f c4012f = C4012f.c;
        return new C4012f(bArr2);
    }

    public final int m0() throws InvalidProtocolBufferException {
        int i = this.g;
        if (this.e - i < 4) {
            s0(4);
            i = this.g;
        }
        this.g = i + 4;
        byte[] bArr = this.d;
        return ((bArr[i + 3] & 255) << 24) | (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final double n() {
        return Double.longBitsToDouble(n0());
    }

    public final long n0() throws InvalidProtocolBufferException {
        int i = this.g;
        if (this.e - i < 8) {
            s0(8);
            i = this.g;
        }
        this.g = i + 8;
        byte[] bArr = this.d;
        return ((bArr[i + 7] & 255) << 56) | (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 6] & 255) << 48);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int o() {
        return o0();
    }

    public final int o0() {
        int i;
        int i2 = this.g;
        int i3 = this.e;
        if (i3 != i2) {
            int i4 = i2 + 1;
            byte[] bArr = this.d;
            byte b = bArr[i2];
            if (b >= 0) {
                this.g = i4;
                return b;
            }
            if (i3 - i4 >= 9) {
                int i5 = i2 + 2;
                int i6 = (bArr[i4] << 7) ^ b;
                if (i6 < 0) {
                    i = i6 ^ (-128);
                } else {
                    int i7 = i2 + 3;
                    int i8 = (bArr[i5] << 14) ^ i6;
                    if (i8 >= 0) {
                        i = i8 ^ 16256;
                    } else {
                        int i9 = i2 + 4;
                        int i10 = i8 ^ (bArr[i7] << 21);
                        if (i10 < 0) {
                            i = (-2080896) ^ i10;
                        } else {
                            i7 = i2 + 5;
                            byte b2 = bArr[i9];
                            int i11 = (i10 ^ (b2 << 28)) ^ 266354560;
                            if (b2 < 0) {
                                i9 = i2 + 6;
                                if (bArr[i7] < 0) {
                                    i7 = i2 + 7;
                                    if (bArr[i9] < 0) {
                                        i9 = i2 + 8;
                                        if (bArr[i7] < 0) {
                                            i7 = i2 + 9;
                                            if (bArr[i9] < 0) {
                                                int i12 = i2 + 10;
                                                if (bArr[i7] >= 0) {
                                                    i5 = i12;
                                                    i = i11;
                                                }
                                            }
                                        }
                                    }
                                }
                                i = i11;
                            }
                            i = i11;
                        }
                        i5 = i9;
                    }
                    i5 = i7;
                }
                this.g = i5;
                return i;
            }
        }
        return (int) q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int p() {
        return m0();
    }

    public final long p0() {
        long j;
        long j2;
        long j3;
        long j4;
        int i = this.g;
        int i2 = this.e;
        if (i2 != i) {
            int i3 = i + 1;
            byte[] bArr = this.d;
            byte b = bArr[i];
            if (b >= 0) {
                this.g = i3;
                return b;
            }
            if (i2 - i3 >= 9) {
                int i4 = i + 2;
                int i5 = (bArr[i3] << 7) ^ b;
                if (i5 < 0) {
                    j = i5 ^ (-128);
                } else {
                    int i6 = i + 3;
                    int i7 = (bArr[i4] << 14) ^ i5;
                    if (i7 >= 0) {
                        j = i7 ^ 16256;
                        i4 = i6;
                    } else {
                        int i8 = i + 4;
                        int i9 = i7 ^ (bArr[i6] << 21);
                        if (i9 < 0) {
                            j4 = (-2080896) ^ i9;
                        } else {
                            long j5 = i9;
                            i4 = i + 5;
                            long j6 = j5 ^ (bArr[i8] << 28);
                            if (j6 >= 0) {
                                j3 = 266354560;
                            } else {
                                i8 = i + 6;
                                long j7 = j6 ^ (bArr[i4] << 35);
                                if (j7 < 0) {
                                    j2 = -34093383808L;
                                } else {
                                    i4 = i + 7;
                                    j6 = j7 ^ (bArr[i8] << 42);
                                    if (j6 >= 0) {
                                        j3 = 4363953127296L;
                                    } else {
                                        i8 = i + 8;
                                        j7 = j6 ^ (bArr[i4] << 49);
                                        if (j7 < 0) {
                                            j2 = -558586000294016L;
                                        } else {
                                            i4 = i + 9;
                                            long j8 = (j7 ^ (bArr[i8] << 56)) ^ 71499008037633920L;
                                            if (j8 < 0) {
                                                int i10 = i + 10;
                                                if (bArr[i4] >= 0) {
                                                    i4 = i10;
                                                }
                                            }
                                            j = j8;
                                        }
                                    }
                                }
                                j4 = j2 ^ j7;
                            }
                            j = j3 ^ j6;
                        }
                        i4 = i8;
                        j = j4;
                    }
                }
                this.g = i4;
                return j;
            }
        }
        return q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long q() {
        return n0();
    }

    public final long q0() throws InvalidProtocolBufferException {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            if (this.g == this.e) {
                s0(1);
            }
            int i2 = this.g;
            this.g = i2 + 1;
            j |= (r3 & Byte.MAX_VALUE) << i;
            if ((this.d[i2] & 128) == 0) {
                return j;
            }
        }
        throw InvalidProtocolBufferException.c();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final float r() {
        return Float.intBitsToFloat(m0());
    }

    public final void r0() {
        int i = this.e + this.f;
        this.e = i;
        int i2 = this.i + i;
        int i3 = this.j;
        if (i2 <= i3) {
            this.f = 0;
            return;
        }
        int i4 = i2 - i3;
        this.f = i4;
        this.e = i - i4;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int s() {
        return o0();
    }

    public final void s0(int i) throws InvalidProtocolBufferException {
        if (u0(i)) {
            return;
        }
        if (i <= (SubsamplingScaleImageView.TILE_SIZE_AUTO - this.i) - this.g) {
            throw InvalidProtocolBufferException.e();
        }
        throw new InvalidProtocolBufferException("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long t() {
        return p0();
    }

    public final void t0(int i) throws InvalidProtocolBufferException {
        int i2 = this.e;
        int i3 = this.g;
        if (i <= i2 - i3 && i >= 0) {
            this.g = i3 + i;
            return;
        }
        InputStream inputStream = this.c;
        if (i < 0) {
            throw InvalidProtocolBufferException.d();
        }
        int i4 = this.i;
        int i5 = i4 + i3;
        int i6 = i5 + i;
        int i7 = this.j;
        if (i6 > i7) {
            t0((i7 - i4) - i3);
            throw InvalidProtocolBufferException.e();
        }
        this.i = i5;
        int i8 = i2 - i3;
        this.e = 0;
        this.g = 0;
        while (i8 < i) {
            long j = i - i8;
            try {
                try {
                    long jSkip = inputStream.skip(j);
                    if (jSkip < 0 || jSkip > j) {
                        throw new IllegalStateException(inputStream.getClass() + "#skip returned invalid result: " + jSkip + "\nThe InputStream implementation is buggy.");
                    }
                    if (jSkip == 0) {
                        break;
                    } else {
                        i8 += (int) jSkip;
                    }
                } catch (InvalidProtocolBufferException e) {
                    e.a = true;
                    throw e;
                }
            } catch (Throwable th) {
                this.i += i8;
                r0();
                throw th;
            }
        }
        this.i += i8;
        r0();
        if (i8 >= i) {
            return;
        }
        int i9 = this.e;
        int i10 = i9 - this.g;
        this.g = i9;
        s0(1);
        while (true) {
            int i11 = i - i10;
            int i12 = this.e;
            if (i11 <= i12) {
                this.g = i11;
                return;
            } else {
                i10 += i12;
                this.g = i12;
                s0(1);
            }
        }
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int u() {
        return m0();
    }

    public final boolean u0(int i) throws IOException {
        int i2 = this.g;
        int i3 = i2 + i;
        int i4 = this.e;
        if (i3 <= i4) {
            throw new IllegalStateException(AbstractC0147y.c(i, "refillBuffer() called when ", " bytes were already available in buffer"));
        }
        int i5 = this.i;
        if (i <= (SubsamplingScaleImageView.TILE_SIZE_AUTO - i5) - i2 && i5 + i2 + i <= this.j) {
            byte[] bArr = this.d;
            if (i2 > 0) {
                if (i4 > i2) {
                    System.arraycopy(bArr, i2, bArr, 0, i4 - i2);
                }
                this.i += i2;
                this.e -= i2;
                this.g = 0;
            }
            int i6 = this.e;
            int iMin = Math.min(bArr.length - i6, (SubsamplingScaleImageView.TILE_SIZE_AUTO - this.i) - i6);
            InputStream inputStream = this.c;
            try {
                int i7 = inputStream.read(bArr, i6, iMin);
                if (i7 == 0 || i7 < -1 || i7 > bArr.length) {
                    throw new IllegalStateException(inputStream.getClass() + "#read(byte[]) returned invalid result: " + i7 + "\nThe InputStream implementation is buggy.");
                }
                if (i7 > 0) {
                    this.e += i7;
                    r0();
                    if (this.e >= i) {
                        return true;
                    }
                    return u0(i);
                }
            } catch (InvalidProtocolBufferException e) {
                e.a = true;
                throw e;
            }
        }
        return false;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long v() {
        return n0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int x() {
        int iO0 = o0();
        return (-(iO0 & 1)) ^ (iO0 >>> 1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long y() {
        long jP0 = p0();
        return (-(jP0 & 1)) ^ (jP0 >>> 1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String z() throws InvalidProtocolBufferException {
        int iO0 = o0();
        byte[] bArr = this.d;
        if (iO0 > 0) {
            int i = this.e;
            int i2 = this.g;
            if (iO0 <= i - i2) {
                String str = new String(bArr, i2, iO0, C.a);
                this.g += iO0;
                return str;
            }
        }
        if (iO0 == 0) {
            return "";
        }
        if (iO0 > this.e) {
            return new String(j0(iO0), C.a);
        }
        s0(iO0);
        String str2 = new String(bArr, this.g, iO0, C.a);
        this.g += iO0;
        return str2;
    }
}
