package com.google.protobuf;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* renamed from: com.google.protobuf.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4013g extends AbstractC1047f0 {
    public final byte[] c;
    public int d;
    public int e;
    public int f;
    public final int g;
    public int h;
    public int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;

    public C4013g(byte[] bArr, int i, int i2, boolean z) {
        this.c = bArr;
        this.d = i2 + i;
        this.f = i;
        this.g = i;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String A() throws InvalidProtocolBufferException {
        int iL0 = l0();
        if (iL0 > 0) {
            int i = this.d;
            int i2 = this.f;
            if (iL0 <= i - i2) {
                String strA = w0.a.a(i2, this.c, iL0);
                this.f += iL0;
                return strA;
            }
        }
        if (iL0 == 0) {
            return "";
        }
        if (iL0 <= 0) {
            throw InvalidProtocolBufferException.d();
        }
        throw InvalidProtocolBufferException.e();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int B() throws InvalidProtocolBufferException {
        if (c()) {
            this.h = 0;
            return 0;
        }
        int iL0 = l0();
        this.h = iL0;
        if ((iL0 >>> 3) != 0) {
            return iL0;
        }
        throw new InvalidProtocolBufferException("Protocol message contained an invalid tag (zero).");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int C() {
        return l0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long D() {
        return m0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean E(int i) throws InvalidProtocolBufferException {
        int iB;
        int i2 = i & 7;
        int i3 = 0;
        if (i2 == 0) {
            int i4 = this.d - this.f;
            byte[] bArr = this.c;
            if (i4 >= 10) {
                while (i3 < 10) {
                    int i5 = this.f;
                    this.f = i5 + 1;
                    if (bArr[i5] < 0) {
                        i3++;
                    }
                }
                throw InvalidProtocolBufferException.c();
            }
            while (i3 < 10) {
                int i6 = this.f;
                if (i6 == this.d) {
                    throw InvalidProtocolBufferException.e();
                }
                this.f = i6 + 1;
                if (bArr[i6] < 0) {
                    i3++;
                }
            }
            throw InvalidProtocolBufferException.c();
            return true;
        }
        if (i2 == 1) {
            p0(8);
            return true;
        }
        if (i2 == 2) {
            p0(l0());
            return true;
        }
        if (i2 != 3) {
            if (i2 == 4) {
                return false;
            }
            if (i2 != 5) {
                throw InvalidProtocolBufferException.b();
            }
            p0(4);
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
        return this.f - this.g;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean c() {
        return this.f == this.d;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final void h(int i) {
        this.i = i;
        o0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int i(int i) throws InvalidProtocolBufferException {
        if (i < 0) {
            throw InvalidProtocolBufferException.d();
        }
        int iB = b() + i;
        if (iB < 0) {
            throw new InvalidProtocolBufferException("Failed to parse the message.");
        }
        int i2 = this.i;
        if (iB > i2) {
            throw InvalidProtocolBufferException.e();
        }
        this.i = iB;
        o0();
        return i2;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean j() {
        return m0() != 0;
    }

    public final int j0() throws InvalidProtocolBufferException {
        int i = this.f;
        if (this.d - i < 4) {
            throw InvalidProtocolBufferException.e();
        }
        this.f = i + 4;
        byte[] bArr = this.c;
        return ((bArr[i + 3] & 255) << 24) | (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16);
    }

    public final long k0() throws InvalidProtocolBufferException {
        int i = this.f;
        if (this.d - i < 8) {
            throw InvalidProtocolBufferException.e();
        }
        this.f = i + 8;
        byte[] bArr = this.c;
        return ((bArr[i + 7] & 255) << 56) | (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 6] & 255) << 48);
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
        return (int) n0();
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x002f  */
    @Override // androidx.core.view.AbstractC1047f0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.protobuf.C4012f m() throws com.google.protobuf.InvalidProtocolBufferException {
        /*
            r4 = this;
            int r0 = r4.l0()
            byte[] r1 = r4.c
            if (r0 <= 0) goto L19
            int r2 = r4.d
            int r3 = r4.f
            int r2 = r2 - r3
            if (r0 > r2) goto L19
            com.google.protobuf.f r1 = com.google.protobuf.C4012f.c(r3, r1, r0)
            int r2 = r4.f
            int r2 = r2 + r0
            r4.f = r2
            return r1
        L19:
            if (r0 != 0) goto L1e
            com.google.protobuf.f r0 = com.google.protobuf.C4012f.c
            return r0
        L1e:
            if (r0 <= 0) goto L2f
            int r2 = r4.d
            int r3 = r4.f
            int r2 = r2 - r3
            if (r0 > r2) goto L2f
            int r0 = r0 + r3
            r4.f = r0
            byte[] r0 = java.util.Arrays.copyOfRange(r1, r3, r0)
            goto L35
        L2f:
            if (r0 > 0) goto L42
            if (r0 != 0) goto L3d
            byte[] r0 = com.google.protobuf.C.b
        L35:
            com.google.protobuf.f r1 = com.google.protobuf.C4012f.c
            com.google.protobuf.f r1 = new com.google.protobuf.f
            r1.<init>(r0)
            return r1
        L3d:
            com.google.protobuf.InvalidProtocolBufferException r0 = com.google.protobuf.InvalidProtocolBufferException.d()
            throw r0
        L42:
            com.google.protobuf.InvalidProtocolBufferException r0 = com.google.protobuf.InvalidProtocolBufferException.e()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.protobuf.C4013g.m():com.google.protobuf.f");
    }

    public final long m0() {
        long j;
        long j2;
        long j3;
        long j4;
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
                this.f = i4;
                return j;
            }
        }
        return n0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final double n() {
        return Double.longBitsToDouble(k0());
    }

    public final long n0() throws InvalidProtocolBufferException {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            int i2 = this.f;
            if (i2 == this.d) {
                throw InvalidProtocolBufferException.e();
            }
            this.f = i2 + 1;
            j |= (r3 & Byte.MAX_VALUE) << i;
            if ((this.c[i2] & 128) == 0) {
                return j;
            }
        }
        throw InvalidProtocolBufferException.c();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int o() {
        return l0();
    }

    public final void o0() {
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

    @Override // androidx.core.view.AbstractC1047f0
    public final int p() {
        return j0();
    }

    public final void p0(int i) throws InvalidProtocolBufferException {
        if (i >= 0) {
            int i2 = this.d;
            int i3 = this.f;
            if (i <= i2 - i3) {
                this.f = i3 + i;
                return;
            }
        }
        if (i >= 0) {
            throw InvalidProtocolBufferException.e();
        }
        throw InvalidProtocolBufferException.d();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long q() {
        return k0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final float r() {
        return Float.intBitsToFloat(j0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int s() {
        return l0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long t() {
        return m0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int u() {
        return j0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long v() {
        return k0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int x() {
        int iL0 = l0();
        return (-(iL0 & 1)) ^ (iL0 >>> 1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long y() {
        long jM0 = m0();
        return (-(jM0 & 1)) ^ (jM0 >>> 1);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String z() throws InvalidProtocolBufferException {
        int iL0 = l0();
        if (iL0 > 0) {
            int i = this.d;
            int i2 = this.f;
            if (iL0 <= i - i2) {
                String str = new String(this.c, i2, iL0, C.a);
                this.f += iL0;
                return str;
            }
        }
        if (iL0 == 0) {
            return "";
        }
        if (iL0 < 0) {
            throw InvalidProtocolBufferException.d();
        }
        throw InvalidProtocolBufferException.e();
    }
}
