package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class EA extends AbstractC1047f0 {
    public final InputStream c;
    public final byte[] d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public /* synthetic */ EA(InputStream inputStream) {
        Charset charset = WA.a;
        this.c = inputStream;
        this.d = new byte[4096];
        this.e = 0;
        this.g = 0;
        this.i = 0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean G() {
        return this.g == this.e && !n0(1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean H() {
        return t0() != 0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final double L() {
        return Double.longBitsToDouble(s0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final float N() {
        return Float.intBitsToFloat(q0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int P() {
        return this.i + this.g;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int R(int i) throws zzgzh {
        if (i < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        int i2 = this.i + this.g + i;
        if (i2 < 0) {
            throw new zzgzh("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit. If reading multiple messages, consider resetting the counter between each message using CodedInputStream.resetSizeCounter().");
        }
        int i3 = this.j;
        if (i2 > i3) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.j = i2;
        l0();
        return i3;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int S() {
        return r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int T() {
        return q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int U() {
        return r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int V() {
        return q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int W() {
        return AbstractC1047f0.I(r0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int X() throws zzgzh {
        if (G()) {
            this.h = 0;
            return 0;
        }
        int iR0 = r0();
        this.h = iR0;
        if ((iR0 >>> 3) != 0) {
            return iR0;
        }
        throw new zzgzh("Protocol message contained an invalid tag (zero).");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int Y() {
        return r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long Z() {
        return s0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long a0() {
        return t0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long b0() {
        return s0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long c0() {
        return AbstractC1047f0.J(t0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long d0() {
        return t0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final C2905zA e0() throws IOException {
        int iR0 = r0();
        int i = this.e;
        int i2 = this.g;
        int i3 = i - i2;
        byte[] bArr = this.d;
        if (iR0 <= i3 && iR0 > 0) {
            C2905zA c2905zAW = BA.w(i2, bArr, iR0);
            this.g += iR0;
            return c2905zAW;
        }
        if (iR0 == 0) {
            return BA.b;
        }
        if (iR0 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        byte[] bArrP0 = p0(iR0);
        if (bArrP0 != null) {
            return BA.w(0, bArrP0, bArrP0.length);
        }
        int i4 = this.g;
        int i5 = this.e;
        int i6 = i5 - i4;
        this.i += i5;
        this.g = 0;
        this.e = 0;
        ArrayList arrayListK0 = k0(iR0 - i6);
        byte[] bArr2 = new byte[iR0];
        System.arraycopy(bArr, i4, bArr2, 0, i6);
        Iterator it2 = arrayListK0.iterator();
        while (it2.hasNext()) {
            byte[] bArr3 = (byte[]) it2.next();
            int length = bArr3.length;
            System.arraycopy(bArr3, 0, bArr2, i6, length);
            i6 += length;
        }
        C2905zA c2905zA = BA.b;
        return new C2905zA(bArr2);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String f0() throws zzgzh {
        int iR0 = r0();
        byte[] bArr = this.d;
        if (iR0 > 0) {
            int i = this.e;
            int i2 = this.g;
            if (iR0 <= i - i2) {
                String str = new String(bArr, i2, iR0, WA.a);
                this.g += iR0;
                return str;
            }
        }
        if (iR0 == 0) {
            return "";
        }
        if (iR0 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        if (iR0 > this.e) {
            return new String(o0(iR0), WA.a);
        }
        m0(iR0);
        String str2 = new String(bArr, this.g, iR0, WA.a);
        this.g += iR0;
        return str2;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String g0() throws IOException {
        int iR0 = r0();
        int i = this.g;
        int i2 = this.e;
        int i3 = i2 - i;
        byte[] bArrO0 = this.d;
        if (iR0 <= i3 && iR0 > 0) {
            this.g = i + iR0;
        } else {
            if (iR0 == 0) {
                return "";
            }
            if (iR0 < 0) {
                throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
            }
            i = 0;
            if (iR0 <= i2) {
                m0(iR0);
                this.g = iR0;
            } else {
                bArrO0 = o0(iR0);
            }
        }
        BB.a.getClass();
        return C2806wy.k(i, bArrO0, iR0);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void h0() throws zzgzh {
        if (this.h != 0) {
            throw new zzgzh("Protocol message end-group tag did not match expected tag.");
        }
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void i0(int i) {
        this.j = i;
        l0();
    }

    public final void j0(int i) throws zzgzh {
        InputStream inputStream = this.c;
        int i2 = this.e;
        int i3 = this.g;
        int i4 = i2 - i3;
        if (i <= i4 && i >= 0) {
            this.g = i3 + i;
            return;
        }
        if (i < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        int i5 = this.i;
        int i6 = i5 + i3;
        int i7 = this.j;
        if (i6 + i > i7) {
            j0((i7 - i5) - i3);
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.i = i6;
        this.e = 0;
        this.g = 0;
        while (i4 < i) {
            long j = i - i4;
            try {
                try {
                    long jSkip = inputStream.skip(j);
                    if (jSkip < 0 || jSkip > j) {
                        throw new IllegalStateException(String.valueOf(inputStream.getClass()) + "#skip returned invalid result: " + jSkip + "\nThe InputStream implementation is buggy.");
                    }
                    if (jSkip == 0) {
                        break;
                    } else {
                        i4 += (int) jSkip;
                    }
                } catch (zzgzh e) {
                    e.a = true;
                    throw e;
                }
            } catch (Throwable th) {
                this.i += i4;
                l0();
                throw th;
            }
        }
        this.i += i4;
        l0();
        if (i4 >= i) {
            return;
        }
        int i8 = this.e;
        int i9 = i8 - this.g;
        this.g = i8;
        m0(1);
        while (true) {
            int i10 = i - i9;
            int i11 = this.e;
            if (i10 <= i11) {
                this.g = i10;
                return;
            } else {
                i9 += i11;
                this.g = i11;
                m0(1);
            }
        }
    }

    public final ArrayList k0(int i) throws IOException {
        ArrayList arrayList = new ArrayList();
        while (i > 0) {
            int iMin = Math.min(i, 4096);
            byte[] bArr = new byte[iMin];
            int i2 = 0;
            while (i2 < iMin) {
                int i3 = this.c.read(bArr, i2, iMin - i2);
                if (i3 == -1) {
                    throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
                }
                this.i += i3;
                i2 += i3;
            }
            i -= iMin;
            arrayList.add(bArr);
        }
        return arrayList;
    }

    public final void l0() {
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

    public final void m0(int i) throws zzgzh {
        if (n0(i)) {
            return;
        }
        if (i <= (SubsamplingScaleImageView.TILE_SIZE_AUTO - this.i) - this.g) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        throw new zzgzh("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit. If reading multiple messages, consider resetting the counter between each message using CodedInputStream.resetSizeCounter().");
    }

    public final boolean n0(int i) throws IOException {
        InputStream inputStream = this.c;
        int i2 = this.g;
        int i3 = i2 + i;
        int i4 = this.e;
        if (i3 <= i4) {
            throw new IllegalStateException(AbstractC0147y.c(i, "refillBuffer() called when ", " bytes were already available in buffer"));
        }
        int i5 = this.i;
        if (i > (SubsamplingScaleImageView.TILE_SIZE_AUTO - i5) - i2 || i5 + i2 + i > this.j) {
            return false;
        }
        byte[] bArr = this.d;
        if (i2 > 0) {
            if (i4 > i2) {
                System.arraycopy(bArr, i2, bArr, 0, i4 - i2);
            }
            i5 = this.i + i2;
            this.i = i5;
            i4 = this.e - i2;
            this.e = i4;
            this.g = 0;
        }
        try {
            int i6 = inputStream.read(bArr, i4, Math.min(4096 - i4, (SubsamplingScaleImageView.TILE_SIZE_AUTO - i5) - i4));
            if (i6 == 0 || i6 < -1 || i6 > 4096) {
                throw new IllegalStateException(String.valueOf(inputStream.getClass()) + "#read(byte[]) returned invalid result: " + i6 + "\nThe InputStream implementation is buggy.");
            }
            if (i6 <= 0) {
                return false;
            }
            this.e += i6;
            l0();
            if (this.e >= i) {
                return true;
            }
            return n0(i);
        } catch (zzgzh e) {
            e.a = true;
            throw e;
        }
    }

    public final byte[] o0(int i) throws IOException {
        byte[] bArrP0 = p0(i);
        if (bArrP0 != null) {
            return bArrP0;
        }
        int i2 = this.g;
        int i3 = this.e;
        int i4 = i3 - i2;
        this.i += i3;
        this.g = 0;
        this.e = 0;
        ArrayList arrayListK0 = k0(i - i4);
        byte[] bArr = new byte[i];
        System.arraycopy(this.d, i2, bArr, 0, i4);
        Iterator it2 = arrayListK0.iterator();
        while (it2.hasNext()) {
            byte[] bArr2 = (byte[]) it2.next();
            int length = bArr2.length;
            System.arraycopy(bArr2, 0, bArr, i4, length);
            i4 += length;
        }
        return bArr;
    }

    public final byte[] p0(int i) throws IOException {
        if (i == 0) {
            return WA.b;
        }
        int i2 = this.i;
        int i3 = this.g;
        int i4 = i2 + i3 + i;
        if ((-2147483647) + i4 > 0) {
            throw new zzgzh("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit. If reading multiple messages, consider resetting the counter between each message using CodedInputStream.resetSizeCounter().");
        }
        int i5 = this.j;
        if (i4 > i5) {
            j0((i5 - i2) - i3);
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        int i6 = this.e - i3;
        int i7 = i - i6;
        InputStream inputStream = this.c;
        if (i7 >= 4096) {
            try {
                if (i7 > inputStream.available()) {
                    return null;
                }
            } catch (zzgzh e) {
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
                    throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
                }
                this.i += i8;
                i6 += i8;
            } catch (zzgzh e2) {
                e2.a = true;
                throw e2;
            }
        }
        return bArr;
    }

    public final int q0() throws zzgzh {
        int i = this.g;
        if (this.e - i < 4) {
            m0(4);
            i = this.g;
        }
        this.g = i + 4;
        byte[] bArr = this.d;
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return ((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16);
    }

    public final int r0() {
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
        return (int) u0();
    }

    public final long s0() throws zzgzh {
        int i = this.g;
        if (this.e - i < 8) {
            m0(8);
            i = this.g;
        }
        this.g = i + 8;
        byte[] bArr = this.d;
        long j = bArr[i];
        long j2 = bArr[i + 2];
        long j3 = bArr[i + 3];
        return ((bArr[i + 6] & 255) << 48) | (j & 255) | ((bArr[i + 1] & 255) << 8) | ((j2 & 255) << 16) | ((j3 & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 7] & 255) << 56);
    }

    public final long t0() {
        long j;
        long j2;
        long j3;
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
                    } else {
                        int i8 = i + 4;
                        int i9 = i7 ^ (bArr[i6] << 21);
                        if (i9 < 0) {
                            long j4 = (-2080896) ^ i9;
                            i4 = i8;
                            j = j4;
                        } else {
                            i6 = i + 5;
                            long j5 = i9 ^ (bArr[i8] << 28);
                            if (j5 >= 0) {
                                j3 = 266354560;
                            } else {
                                int i10 = i + 6;
                                long j6 = j5 ^ (bArr[i6] << 35);
                                if (j6 < 0) {
                                    j2 = -34093383808L;
                                } else {
                                    i6 = i + 7;
                                    j5 = j6 ^ (bArr[i10] << 42);
                                    if (j5 >= 0) {
                                        j3 = 4363953127296L;
                                    } else {
                                        i10 = i + 8;
                                        j6 = j5 ^ (bArr[i6] << 49);
                                        if (j6 < 0) {
                                            j2 = -558586000294016L;
                                        } else {
                                            i6 = i + 9;
                                            long j7 = (j6 ^ (bArr[i10] << 56)) ^ 71499008037633920L;
                                            if (j7 < 0) {
                                                int i11 = i + 10;
                                                if (bArr[i6] >= 0) {
                                                    j = j7;
                                                    i4 = i11;
                                                }
                                            } else {
                                                j = j7;
                                            }
                                        }
                                    }
                                }
                                j = j6 ^ j2;
                                i4 = i10;
                            }
                            j = j5 ^ j3;
                        }
                    }
                    i4 = i6;
                }
                this.g = i4;
                return j;
            }
        }
        return u0();
    }

    public final long u0() throws zzgzh {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            if (this.g == this.e) {
                m0(1);
            }
            int i2 = this.g;
            this.g = i2 + 1;
            j |= (r3 & Byte.MAX_VALUE) << i;
            if ((this.d[i2] & 128) == 0) {
                return j;
            }
        }
        throw new zzgzh("CodedInputStream encountered a malformed varint.");
    }
}
