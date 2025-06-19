package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class DA extends AbstractC1047f0 {
    public final Iterator c;
    public ByteBuffer d;
    public int e;
    public int f;
    public int h;
    public long j;
    public long k;
    public long l;
    public int g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
    public int i = 0;

    public /* synthetic */ DA(int i, ArrayList arrayList) {
        this.e = i;
        this.c = arrayList.iterator();
        if (i != 0) {
            m0();
            return;
        }
        this.d = WA.c;
        this.j = 0L;
        this.k = 0L;
        this.l = 0L;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean G() {
        return (((long) this.i) + this.j) - this.k == ((long) this.e);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final boolean H() {
        return r0() != 0;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final double L() {
        return Double.longBitsToDouble(q0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final float N() {
        return Float.intBitsToFloat(o0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int P() {
        return (int) ((this.i + this.j) - this.k);
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int R(int i) throws zzgzh {
        if (i < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        int iP = P() + i;
        int i2 = this.g;
        if (iP > i2) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        this.g = iP;
        int i3 = this.e + this.f;
        this.e = i3;
        if (i3 <= iP) {
            this.f = 0;
            return i2;
        }
        int i4 = i3 - iP;
        this.f = i4;
        this.e = i3 - i4;
        return i2;
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int S() {
        return p0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int T() {
        return o0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int U() {
        return p0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int V() {
        return o0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int W() {
        return AbstractC1047f0.I(p0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int X() throws zzgzh {
        if (G()) {
            this.h = 0;
            return 0;
        }
        int iP0 = p0();
        this.h = iP0;
        if ((iP0 >>> 3) != 0) {
            return iP0;
        }
        throw new zzgzh("Protocol message contained an invalid tag (zero).");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final int Y() {
        return p0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long Z() {
        return q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long a0() {
        return r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long b0() {
        return q0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long c0() {
        return AbstractC1047f0.J(r0());
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final long d0() {
        return r0();
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final C2905zA e0() throws zzgzh {
        int iP0 = p0();
        if (iP0 > 0) {
            long j = this.l;
            long j2 = this.j;
            long j3 = iP0;
            if (j3 <= j - j2) {
                byte[] bArr = new byte[iP0];
                AbstractC2906zB.c.Z0(j2, bArr, 0L, j3);
                this.j += j3;
                C2905zA c2905zA = BA.b;
                return new C2905zA(bArr);
            }
        }
        if (iP0 > 0 && iP0 <= k0()) {
            byte[] bArr2 = new byte[iP0];
            l0(iP0, bArr2);
            C2905zA c2905zA2 = BA.b;
            return new C2905zA(bArr2);
        }
        if (iP0 == 0) {
            return BA.b;
        }
        if (iP0 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String f0() throws zzgzh {
        int iP0 = p0();
        if (iP0 > 0) {
            long j = this.l;
            long j2 = this.j;
            long j3 = iP0;
            if (j3 <= j - j2) {
                byte[] bArr = new byte[iP0];
                AbstractC2906zB.c.Z0(j2, bArr, 0L, j3);
                String str = new String(bArr, WA.a);
                this.j += j3;
                return str;
            }
        }
        if (iP0 > 0 && iP0 <= k0()) {
            byte[] bArr2 = new byte[iP0];
            l0(iP0, bArr2);
            return new String(bArr2, WA.a);
        }
        if (iP0 == 0) {
            return "";
        }
        if (iP0 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    @Override // androidx.core.view.AbstractC1047f0
    public final String g0() throws zzgzh {
        String strL;
        int iP0 = p0();
        if (iP0 > 0) {
            long j = this.l;
            long j2 = this.j;
            long j3 = iP0;
            if (j3 <= j - j2) {
                long j4 = j2 - this.k;
                ByteBuffer byteBuffer = this.d;
                int i = (int) j4;
                C2806wy c2806wy = BB.a;
                if (byteBuffer.hasArray()) {
                    int iArrayOffset = byteBuffer.arrayOffset();
                    byte[] bArrArray = byteBuffer.array();
                    BB.a.getClass();
                    strL = C2806wy.k(iArrayOffset + i, bArrArray, iP0);
                } else {
                    strL = byteBuffer.isDirect() ? C2806wy.l(byteBuffer, i, iP0) : C2806wy.l(byteBuffer, i, iP0);
                }
                this.j += j3;
                return strL;
            }
        }
        if (iP0 >= 0 && iP0 <= k0()) {
            byte[] bArr = new byte[iP0];
            l0(iP0, bArr);
            BB.a.getClass();
            return C2806wy.k(0, bArr, iP0);
        }
        if (iP0 == 0) {
            return "";
        }
        if (iP0 <= 0) {
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
        this.g = i;
        int i2 = this.e + this.f;
        this.e = i2;
        if (i2 <= i) {
            this.f = 0;
            return;
        }
        int i3 = i2 - i;
        this.f = i3;
        this.e = i2 - i3;
    }

    public final long j0() throws zzgzh {
        long j = 0;
        for (int i = 0; i < 64; i += 7) {
            j |= (r3 & Byte.MAX_VALUE) << i;
            if ((n0() & 128) == 0) {
                return j;
            }
        }
        throw new zzgzh("CodedInputStream encountered a malformed varint.");
    }

    public final int k0() {
        return (int) (((this.e - this.i) - this.j) + this.k);
    }

    public final void l0(int i, byte[] bArr) throws zzgzh {
        if (i > k0()) {
            if (i > 0) {
                throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            return;
        }
        int i2 = i;
        while (i2 > 0) {
            if (this.l - this.j == 0) {
                if (!this.c.hasNext()) {
                    throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
                }
                m0();
            }
            int iMin = Math.min(i2, (int) (this.l - this.j));
            long j = iMin;
            byte[] bArr2 = bArr;
            AbstractC2906zB.c.Z0(this.j, bArr2, i - i2, j);
            i2 -= iMin;
            this.j += j;
            bArr = bArr2;
        }
    }

    public final void m0() {
        ByteBuffer byteBuffer = (ByteBuffer) this.c.next();
        this.d = byteBuffer;
        this.i += (int) (this.j - this.k);
        long jPosition = byteBuffer.position();
        this.j = jPosition;
        this.k = jPosition;
        this.l = this.d.limit();
        long jF = AbstractC2906zB.f(this.d);
        this.j += jF;
        this.k += jF;
        this.l += jF;
    }

    public final byte n0() throws zzgzh {
        if (this.l - this.j == 0) {
            if (!this.c.hasNext()) {
                throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            m0();
        }
        long j = this.j;
        this.j = 1 + j;
        return AbstractC2906zB.c.U0(j);
    }

    public final int o0() {
        long j = this.l;
        long j2 = this.j;
        if (j - j2 < 4) {
            int iN0 = n0() & 255;
            int iN02 = (n0() & 255) << 8;
            return iN0 | iN02 | ((n0() & 255) << 16) | ((n0() & 255) << 24);
        }
        this.j = 4 + j2;
        AbstractC2863yB abstractC2863yB = AbstractC2906zB.c;
        int iU0 = abstractC2863yB.U0(j2) & 255;
        int iU02 = (abstractC2863yB.U0(1 + j2) & 255) << 8;
        return ((abstractC2863yB.U0(j2 + 3) & 255) << 24) | iU0 | iU02 | ((abstractC2863yB.U0(2 + j2) & 255) << 16);
    }

    public final int p0() {
        int i;
        long j = this.j;
        if (this.l != j) {
            long j2 = j + 1;
            AbstractC2863yB abstractC2863yB = AbstractC2906zB.c;
            byte bU0 = abstractC2863yB.U0(j);
            if (bU0 >= 0) {
                this.j++;
                return bU0;
            }
            if (this.l - this.j >= 10) {
                long j3 = 2 + j;
                int iU0 = (abstractC2863yB.U0(j2) << 7) ^ bU0;
                if (iU0 < 0) {
                    i = iU0 ^ (-128);
                } else {
                    long j4 = 3 + j;
                    int iU02 = (abstractC2863yB.U0(j3) << 14) ^ iU0;
                    if (iU02 >= 0) {
                        i = iU02 ^ 16256;
                    } else {
                        long j5 = 4 + j;
                        int iU03 = iU02 ^ (abstractC2863yB.U0(j4) << 21);
                        if (iU03 < 0) {
                            i = (-2080896) ^ iU03;
                        } else {
                            j4 = 5 + j;
                            byte bU02 = abstractC2863yB.U0(j5);
                            int i2 = (iU03 ^ (bU02 << 28)) ^ 266354560;
                            if (bU02 < 0) {
                                j5 = 6 + j;
                                if (abstractC2863yB.U0(j4) < 0) {
                                    j4 = 7 + j;
                                    if (abstractC2863yB.U0(j5) < 0) {
                                        j5 = 8 + j;
                                        if (abstractC2863yB.U0(j4) < 0) {
                                            j4 = 9 + j;
                                            if (abstractC2863yB.U0(j5) < 0) {
                                                long j6 = j + 10;
                                                if (abstractC2863yB.U0(j4) >= 0) {
                                                    i = i2;
                                                    j3 = j6;
                                                }
                                            }
                                        }
                                    }
                                }
                                i = i2;
                            }
                            i = i2;
                        }
                        j3 = j5;
                    }
                    j3 = j4;
                }
                this.j = j3;
                return i;
            }
        }
        return (int) j0();
    }

    public final long q0() {
        long j = this.l;
        long j2 = this.j;
        if (j - j2 < 8) {
            return ((n0() & 255) << 56) | (n0() & 255) | ((n0() & 255) << 8) | ((n0() & 255) << 16) | ((n0() & 255) << 24) | ((n0() & 255) << 32) | ((n0() & 255) << 40) | ((n0() & 255) << 48);
        }
        this.j = 8 + j2;
        AbstractC2863yB abstractC2863yB = AbstractC2906zB.c;
        return (abstractC2863yB.U0(j2) & 255) | ((abstractC2863yB.U0(j2 + 1) & 255) << 8) | ((abstractC2863yB.U0(j2 + 2) & 255) << 16) | ((abstractC2863yB.U0(j2 + 3) & 255) << 24) | ((abstractC2863yB.U0(j2 + 4) & 255) << 32) | ((abstractC2863yB.U0(j2 + 5) & 255) << 40) | ((abstractC2863yB.U0(j2 + 6) & 255) << 48) | ((abstractC2863yB.U0(j2 + 7) & 255) << 56);
    }

    public final long r0() {
        long j;
        long j2;
        long j3;
        long j4 = this.j;
        if (this.l != j4) {
            long j5 = j4 + 1;
            AbstractC2863yB abstractC2863yB = AbstractC2906zB.c;
            byte bU0 = abstractC2863yB.U0(j4);
            if (bU0 >= 0) {
                this.j++;
                return bU0;
            }
            if (this.l - this.j >= 10) {
                long j6 = 2 + j4;
                int iU0 = (abstractC2863yB.U0(j5) << 7) ^ bU0;
                if (iU0 < 0) {
                    j = iU0 ^ (-128);
                } else {
                    long j7 = 3 + j4;
                    int iU02 = (abstractC2863yB.U0(j6) << 14) ^ iU0;
                    if (iU02 >= 0) {
                        j = iU02 ^ 16256;
                    } else {
                        long j8 = 4 + j4;
                        int iU03 = iU02 ^ (abstractC2863yB.U0(j7) << 21);
                        if (iU03 < 0) {
                            j = (-2080896) ^ iU03;
                            j6 = j8;
                        } else {
                            j7 = 5 + j4;
                            long jU0 = (abstractC2863yB.U0(j8) << 28) ^ iU03;
                            if (jU0 >= 0) {
                                j3 = 266354560;
                            } else {
                                long j9 = 6 + j4;
                                long jU02 = jU0 ^ (abstractC2863yB.U0(j7) << 35);
                                if (jU02 < 0) {
                                    j2 = -34093383808L;
                                } else {
                                    j7 = 7 + j4;
                                    jU0 = jU02 ^ (abstractC2863yB.U0(j9) << 42);
                                    if (jU0 >= 0) {
                                        j3 = 4363953127296L;
                                    } else {
                                        j9 = 8 + j4;
                                        jU02 = jU0 ^ (abstractC2863yB.U0(j7) << 49);
                                        if (jU02 < 0) {
                                            j2 = -558586000294016L;
                                        } else {
                                            j7 = 9 + j4;
                                            long jU03 = (jU02 ^ (abstractC2863yB.U0(j9) << 56)) ^ 71499008037633920L;
                                            if (jU03 < 0) {
                                                long j10 = j4 + 10;
                                                if (abstractC2863yB.U0(j7) >= 0) {
                                                    j6 = j10;
                                                    j = jU03;
                                                }
                                            } else {
                                                j = jU03;
                                            }
                                        }
                                    }
                                }
                                j = j2 ^ jU02;
                                j6 = j9;
                            }
                            j = j3 ^ jU0;
                        }
                    }
                    j6 = j7;
                }
                this.j = j6;
                return j;
            }
        }
        return j0();
    }
}
