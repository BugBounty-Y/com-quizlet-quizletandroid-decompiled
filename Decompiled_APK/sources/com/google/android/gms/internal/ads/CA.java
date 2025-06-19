package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class CA extends AbstractC1047f0 {
    public final byte[] c;
    public int d;
    public int e;
    public int f;
    public final int g;
    public int h;
    public int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public /* synthetic */ CA(int i, byte[] bArr, int i2) {
        this.c = bArr;
        this.d = i2 + i;
        this.f = i;
        this.g = i;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean G() {
        return this.f == this.d;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean H() {
        return n0() != 0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final double L() {
        return Double.longBitsToDouble(m0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final float N() {
        return Float.intBitsToFloat(k0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int P() {
        return this.f - this.g;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int R(int i) {
        if (i < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        int i2 = (this.f - this.g) + i;
        if (i2 < 0) {
            throw new zzgzh("Protocol message was too large.  May be malicious.  Use CodedInputStream.setSizeLimit() to increase the size limit. If reading multiple messages, consider resetting the counter between each message using CodedInputStream.resetSizeCounter().");
        }
        int i3 = this.i;
        if (i2 > i3) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.i = i2;
        j0();
        return i3;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int S() {
        return l0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int T() {
        return k0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int U() {
        return l0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int V() {
        return k0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int W() {
        return AbstractC1047f0.I(l0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int X() throws zzgzh {
        if (G()) {
            this.h = 0;
            return 0;
        }
        int iL0 = l0();
        this.h = iL0;
        if ((iL0 >>> 3) != 0) {
            return iL0;
        }
        throw new zzgzh("Protocol message contained an invalid tag (zero).");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int Y() {
        return l0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long Z() {
        return m0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long a0() {
        return n0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long b0() {
        return m0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long c0() {
        return AbstractC1047f0.J(n0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long d0() {
        return n0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final C2905zA e0() throws zzgzh {
        int iL0 = l0();
        byte[] bArr = this.c;
        if (iL0 > 0) {
            int i = this.d;
            int i2 = this.f;
            if (iL0 <= i - i2) {
                C2905zA c2905zAW = BA.w(i2, bArr, iL0);
                this.f += iL0;
                return c2905zAW;
            }
        }
        if (iL0 == 0) {
            return BA.b;
        }
        if (iL0 > 0) {
            int i3 = this.d;
            int i4 = this.f;
            if (iL0 <= i3 - i4) {
                int i5 = iL0 + i4;
                this.f = i5;
                byte[] bArrCopyOfRange = Arrays.copyOfRange(bArr, i4, i5);
                C2905zA c2905zA = BA.b;
                return new C2905zA(bArrCopyOfRange);
            }
        }
        if (iL0 <= 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String f0() throws zzgzh {
        int iL0 = l0();
        if (iL0 > 0) {
            int i = this.d;
            int i2 = this.f;
            if (iL0 <= i - i2) {
                String str = new String(this.c, i2, iL0, WA.a);
                this.f += iL0;
                return str;
            }
        }
        if (iL0 == 0) {
            return "";
        }
        if (iL0 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String g0() throws zzgzh {
        int iL0 = l0();
        if (iL0 > 0) {
            int i = this.d;
            int i2 = this.f;
            if (iL0 <= i - i2) {
                BB.a.getClass();
                String strK = C2806wy.k(i2, this.c, iL0);
                this.f += iL0;
                return strK;
            }
        }
        if (iL0 == 0) {
            return "";
        }
        if (iL0 <= 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void h0() throws zzgzh {
        if (this.h != 0) {
            throw new zzgzh("Protocol message end-group tag did not match expected tag.");
        }
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void i0(int i) {
        this.i = i;
        j0();
    }

    public final void j0() {
        int i = this.d + this.e;
        this.d = i;
        int i2 = i - this.g;
        int i3 = this.i;
        if (i2 <= i3) {
            this.e = 0;
            return;
        }
        int i4 = i2 - i3;
        this.e = i4;
        this.d = i - i4;
    }

    public final int k0() throws zzgzh {
        int i = this.f;
        if (this.d - i < 4) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.f = i + 4;
        byte[] bArr = this.c;
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return ((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16);
    }

    public final int l0() {
        int i;
        int i2 = this.f;
        int i3 = this.d;
        if (i3 != i2) {
            int i4 = i2 + 1;
            byte[] bArr = this.c;
            byte b = bArr[i2];
            if (b >= 0) {
                this.f = i4;
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
                this.f = i5;
                return i;
            }
        }
        return (int) o0();
    }

    public final long m0() throws zzgzh {
        int i = this.f;
        if (this.d - i < 8) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.f = i + 8;
        byte[] bArr = this.c;
        long j = bArr[i];
        long j2 = bArr[i + 2];
        long j3 = bArr[i + 3];
        return ((bArr[i + 6] & 255) << 48) | (j & 255) | ((bArr[i + 1] & 255) << 8) | ((j2 & 255) << 16) | ((j3 & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 7] & 255) << 56);
    }

    public final long n0() {
        long j;
        long j2;
        long j3;
        int i = this.f;
        int i2 = this.d;
        if (i2 != i) {
            int i3 = i + 1;
            byte[] bArr = this.c;
            byte b = bArr[i];
            if (b >= 0) {
                this.f = i3;
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
                this.f = i4;
                return j;
            }
        }
        return o0();
    }

    public final long o0() throws zzgzh {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            int i2 = this.f;
            if (i2 == this.d) {
                throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            this.f = i2 + 1;
            j |= (r3 & Byte.MAX_VALUE) << i;
            if ((this.c[i2] & 128) == 0) {
                return j;
            }
        }
        throw new zzgzh("CodedInputStream encountered a malformed varint.");
    }
}
