package okio;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends k {
    public final transient byte[][] e;
    public final transient int[] f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(byte[][] segments, int[] directory) {
        super(k.d.a);
        Intrinsics.checkNotNullParameter(segments, "segments");
        Intrinsics.checkNotNullParameter(directory, "directory");
        this.e = segments;
        this.f = directory;
    }

    private final Object writeReplace() {
        return v();
    }

    @Override // okio.k
    public final String a() {
        throw null;
    }

    @Override // okio.k
    public final k c(String algorithm) throws NoSuchAlgorithmException {
        Intrinsics.checkNotNullParameter(algorithm, "algorithm");
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        byte[][] bArr = this.e;
        int length = bArr.length;
        int i = 0;
        int i2 = 0;
        while (i < length) {
            int[] iArr = this.f;
            int i3 = iArr[length + i];
            int i4 = iArr[i];
            messageDigest.update(bArr[i], i3, i4 - i2);
            i++;
            i2 = i4;
        }
        byte[] bArrDigest = messageDigest.digest();
        Intrinsics.d(bArrDigest);
        return new k(bArrDigest);
    }

    @Override // okio.k
    public final int d() {
        return this.f[this.e.length - 1];
    }

    @Override // okio.k
    public final String e() {
        return v().e();
    }

    @Override // okio.k
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof k) {
            k kVar = (k) obj;
            if (kVar.d() == d() && n(0, kVar, d())) {
                return true;
            }
        }
        return false;
    }

    @Override // okio.k
    public final int f(int i, byte[] other) {
        Intrinsics.checkNotNullParameter(other, "other");
        return v().f(i, other);
    }

    @Override // okio.k
    public final byte[] h() {
        return u();
    }

    @Override // okio.k
    public final int hashCode() {
        int i = this.b;
        if (i != 0) {
            return i;
        }
        byte[][] bArr = this.e;
        int length = bArr.length;
        int i2 = 0;
        int i3 = 1;
        int i4 = 0;
        while (i2 < length) {
            int[] iArr = this.f;
            int i5 = iArr[length + i2];
            int i6 = iArr[i2];
            byte[] bArr2 = bArr[i2];
            int i7 = (i6 - i4) + i5;
            while (i5 < i7) {
                i3 = (i3 * 31) + bArr2[i5];
                i5++;
            }
            i2++;
            i4 = i6;
        }
        this.b = i3;
        return i3;
    }

    @Override // okio.k
    public final byte j(int i) {
        byte[][] bArr = this.e;
        int length = bArr.length - 1;
        int[] iArr = this.f;
        AbstractC5085b.e(iArr[length], i, 1L);
        int i2 = okio.internal.b.i(this, i);
        return bArr[i2][(i - (i2 == 0 ? 0 : iArr[i2 - 1])) + iArr[bArr.length + i2]];
    }

    @Override // okio.k
    public final int k(byte[] other) {
        Intrinsics.checkNotNullParameter(other, "other");
        return v().k(other);
    }

    @Override // okio.k
    public final boolean m(int i, int i2, byte[] other, int i3) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (i < 0 || i > d() - i3 || i2 < 0 || i2 > other.length - i3) {
            return false;
        }
        int i4 = i3 + i;
        int i5 = okio.internal.b.i(this, i);
        while (i < i4) {
            int[] iArr = this.f;
            int i6 = i5 == 0 ? 0 : iArr[i5 - 1];
            int i7 = iArr[i5] - i6;
            byte[][] bArr = this.e;
            int i8 = iArr[bArr.length + i5];
            int iMin = Math.min(i4, i7 + i6) - i;
            if (!AbstractC5085b.a((i - i6) + i8, i2, iMin, bArr[i5], other)) {
                return false;
            }
            i2 += iMin;
            i += iMin;
            i5++;
        }
        return true;
    }

    @Override // okio.k
    public final boolean n(int i, k other, int i2) {
        Intrinsics.checkNotNullParameter(other, "other");
        if (i >= 0 && i <= d() - i2) {
            int i3 = i2 + i;
            int i4 = okio.internal.b.i(this, i);
            int i5 = 0;
            while (i < i3) {
                int[] iArr = this.f;
                int i6 = i4 == 0 ? 0 : iArr[i4 - 1];
                int i7 = iArr[i4] - i6;
                byte[][] bArr = this.e;
                int i8 = iArr[bArr.length + i4];
                int iMin = Math.min(i3, i7 + i6) - i;
                if (other.m(i5, (i - i6) + i8, bArr[i4], iMin)) {
                    i5 += iMin;
                    i += iMin;
                    i4++;
                }
            }
            return true;
        }
        return false;
    }

    @Override // okio.k
    public final k o(int i, int i2) {
        Intrinsics.checkNotNullParameter(this, "<this>");
        if (i2 == -1234567890) {
            i2 = d();
        }
        if (i < 0) {
            throw new IllegalArgumentException(AbstractC0147y.c(i, "beginIndex=", " < 0").toString());
        }
        if (i2 > d()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i2, "endIndex=", " > length(");
            sbV.append(d());
            sbV.append(')');
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        int i3 = i2 - i;
        if (i3 < 0) {
            throw new IllegalArgumentException(d0.p("endIndex=", i2, " < beginIndex=", i).toString());
        }
        if (i == 0 && i2 == d()) {
            return this;
        }
        if (i == i2) {
            return k.d;
        }
        int i4 = okio.internal.b.i(this, i);
        int i5 = okio.internal.b.i(this, i2 - 1);
        byte[][] bArr = this.e;
        byte[][] bArr2 = (byte[][]) C4930v.n(i4, i5 + 1, bArr);
        int[] iArr = new int[bArr2.length * 2];
        int[] iArr2 = this.f;
        if (i4 <= i5) {
            int i6 = i4;
            int i7 = 0;
            while (true) {
                iArr[i7] = Math.min(iArr2[i6] - i, i3);
                int i8 = i7 + 1;
                iArr[i7 + bArr2.length] = iArr2[bArr.length + i6];
                if (i6 == i5) {
                    break;
                }
                i6++;
                i7 = i8;
            }
        }
        int i9 = i4 != 0 ? iArr2[i4 - 1] : 0;
        int length = bArr2.length;
        iArr[length] = (i - i9) + iArr[length];
        return new D(bArr2, iArr);
    }

    @Override // okio.k
    public final k q() {
        return v().q();
    }

    @Override // okio.k
    public final void t(C5091h buffer, int i) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        int i2 = okio.internal.b.i(this, 0);
        int i3 = 0;
        while (i3 < i) {
            int[] iArr = this.f;
            int i4 = i2 == 0 ? 0 : iArr[i2 - 1];
            int i5 = iArr[i2] - i4;
            byte[][] bArr = this.e;
            int i6 = iArr[bArr.length + i2];
            int iMin = Math.min(i, i5 + i4) - i3;
            int i7 = (i3 - i4) + i6;
            B b = new B(bArr[i2], i7, i7 + iMin, true, false);
            B b2 = buffer.a;
            if (b2 == null) {
                b.g = b;
                b.f = b;
                buffer.a = b;
            } else {
                B b3 = b2.g;
                Intrinsics.d(b3);
                b3.b(b);
            }
            i3 += iMin;
            i2++;
        }
        buffer.b += i;
    }

    @Override // okio.k
    public final String toString() {
        return v().toString();
    }

    public final byte[] u() {
        byte[] bArr = new byte[d()];
        byte[][] bArr2 = this.e;
        int length = bArr2.length;
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        while (i < length) {
            int[] iArr = this.f;
            int i4 = iArr[length + i];
            int i5 = iArr[i];
            int i6 = i5 - i2;
            C4930v.d(i3, i4, i4 + i6, bArr2[i], bArr);
            i3 += i6;
            i++;
            i2 = i5;
        }
        return bArr;
    }

    public final k v() {
        return new k(u());
    }
}
