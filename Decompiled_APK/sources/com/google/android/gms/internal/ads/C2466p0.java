package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.p0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2466p0 {
    public final /* synthetic */ int a;
    public byte[] b;
    public int c;
    public int d;
    public int e;

    public C2466p0(int i, byte[] bArr) {
        this.a = 1;
        this.b = bArr;
        this.e = i;
    }

    public int a() {
        return ((this.e - this.c) * 8) - this.d;
    }

    public int b(int i) {
        int i2;
        byte[] bArr;
        this.e += i;
        int i3 = 0;
        while (true) {
            i2 = this.e;
            bArr = this.b;
            if (i2 <= 8) {
                break;
            }
            int i4 = i2 - 8;
            this.e = i4;
            int i5 = this.d;
            i3 |= (bArr[i5] & 255) << i4;
            if (true != r(i5 + 1)) {
                i = 1;
            }
            this.d = i5 + i;
        }
        int i6 = this.d;
        int i7 = i3 | ((bArr[i6] & 255) >> (8 - i2));
        int i8 = 32 - i;
        if (i2 == 8) {
            this.e = 0;
            this.d = i6 + (true != r(i6 + 1) ? 1 : 2);
        }
        int i9 = ((-1) >>> i8) & i7;
        p();
        return i9;
    }

    public int c() {
        switch (this.a) {
            case 1:
                AbstractC1795We.L(this.d == 0);
                return this.c;
            default:
                int iO = o();
                int i = iO % 2;
                return ((iO + 1) / 2) * (i == 0 ? -1 : 1);
        }
    }

    public int d(int i) {
        int i2 = this.d;
        int i3 = i2 + 1;
        int iMin = Math.min(i, 8 - this.e);
        byte[] bArr = this.b;
        int i4 = ((bArr[i2] & 255) >> this.e) & (255 >> (8 - iMin));
        while (iMin < i) {
            i4 |= (bArr[i3] & 255) << iMin;
            iMin += 8;
            i3++;
        }
        int i5 = i4 & ((-1) >>> (32 - i));
        e(i);
        return i5;
    }

    public void e(int i) {
        int i2;
        int i3 = i / 8;
        int i4 = this.d + i3;
        this.d = i4;
        int i5 = (i - (i3 * 8)) + this.e;
        this.e = i5;
        if (i5 > 7) {
            i4++;
            this.d = i4;
            i5 -= 8;
            this.e = i5;
        }
        boolean z = false;
        if (i4 >= 0 && (i4 < (i2 = this.c) || (i4 == i2 && i5 == 0))) {
            z = true;
        }
        AbstractC1795We.L(z);
    }

    public int f(int i) {
        int i2;
        if (i == 0) {
            return 0;
        }
        this.d += i;
        int i3 = 0;
        while (true) {
            i2 = this.d;
            if (i2 <= 8) {
                break;
            }
            int i4 = i2 - 8;
            this.d = i4;
            byte[] bArr = this.b;
            int i5 = this.c;
            this.c = i5 + 1;
            i3 |= (bArr[i5] & 255) << i4;
        }
        byte[] bArr2 = this.b;
        int i6 = this.c;
        int i7 = i3 | ((bArr2[i6] & 255) >> (8 - i2));
        int i8 = 32 - i;
        if (i2 == 8) {
            this.d = 0;
            this.c = i6 + 1;
        }
        int i9 = ((-1) >>> i8) & i7;
        x();
        return i9;
    }

    public boolean g() {
        int i = (this.b[this.d] & 255) >> this.e;
        e(1);
        return 1 == (i & 1);
    }

    public long h(int i) {
        if (i <= 32) {
            int iF = f(i);
            String str = Yo.a;
            return 4294967295L & iF;
        }
        int iF2 = f(i - 32);
        int iF3 = f(32);
        String str2 = Yo.a;
        return (4294967295L & iF3) | ((iF2 & 4294967295L) << 32);
    }

    public void i() {
        int i = this.e + 1;
        this.e = i;
        if (i == 8) {
            this.e = 0;
            int i2 = this.d;
            this.d = i2 + (true == r(i2 + 1) ? 2 : 1);
        }
        p();
    }

    public void j() {
        if (this.d == 0) {
            return;
        }
        this.d = 0;
        this.c++;
        x();
    }

    public void k(int i) {
        int i2 = this.d;
        int i3 = i / 8;
        int i4 = i2 + i3;
        this.d = i4;
        int i5 = (i - (i3 * 8)) + this.e;
        this.e = i5;
        if (i5 > 7) {
            this.d = i4 + 1;
            this.e = i5 - 8;
        }
        while (true) {
            i2++;
            if (i2 > this.d) {
                p();
                return;
            } else if (r(i2)) {
                this.d++;
                i2 += 2;
            }
        }
    }

    public boolean l(int i) {
        int i2;
        int i3 = this.d;
        int i4 = i / 8;
        int i5 = i3 + i4;
        int i6 = (this.e + i) - (i4 * 8);
        if (i6 > 7) {
            i5++;
            i6 -= 8;
        }
        while (true) {
            i3++;
            i2 = this.c;
            if (i3 > i5 || i5 >= i2) {
                break;
            }
            if (r(i3)) {
                i5++;
                i3 += 2;
            }
        }
        if (i5 >= i2) {
            return i5 == i2 && i6 == 0;
        }
        return true;
    }

    public void m(int i, byte[] bArr) {
        int i2;
        int i3 = 0;
        while (true) {
            i2 = i >> 3;
            if (i3 >= i2) {
                break;
            }
            byte[] bArr2 = this.b;
            int i4 = this.c;
            int i5 = i4 + 1;
            this.c = i5;
            byte b = bArr2[i4];
            int i6 = this.d;
            byte b2 = (byte) (b << i6);
            bArr[i3] = b2;
            bArr[i3] = (byte) (((bArr2[i5] & 255) >> (8 - i6)) | b2);
            i3++;
        }
        int i7 = i & 7;
        if (i7 == 0) {
            return;
        }
        byte b3 = (byte) (bArr[i2] & (255 >> i7));
        bArr[i2] = b3;
        int i8 = this.d;
        if (i8 + i7 > 8) {
            byte[] bArr3 = this.b;
            int i9 = this.c;
            this.c = i9 + 1;
            b3 = (byte) (b3 | ((bArr3[i9] & 255) << i8));
            bArr[i2] = b3;
            i8 -= 8;
        }
        int i10 = i8 + i7;
        this.d = i10;
        byte[] bArr4 = this.b;
        int i11 = this.c;
        bArr[i2] = (byte) (((byte) (((255 & bArr4[i11]) >> (8 - i10)) << (8 - i7))) | b3);
        if (i10 == 8) {
            this.d = 0;
            this.c = i11 + 1;
        }
        x();
    }

    public boolean n() {
        int i = this.b[this.d] & (128 >> this.e);
        i();
        return i != 0;
    }

    public int o() {
        int i = 0;
        while (!n()) {
            i++;
        }
        return ((1 << i) - 1) + (i > 0 ? b(i) : 0);
    }

    public void p() {
        int i;
        int i2 = this.d;
        boolean z = false;
        if (i2 >= 0 && (i2 < (i = this.c) || (i2 == i && this.e == 0))) {
            z = true;
        }
        AbstractC1795We.L(z);
    }

    public void q(Kn kn) {
        byte[] bArr = kn.a;
        int i = kn.c;
        this.b = bArr;
        this.c = 0;
        this.d = 0;
        this.e = i;
        s(kn.b * 8);
    }

    public boolean r(int i) {
        if (i < 2 || i >= this.c) {
            return false;
        }
        byte[] bArr = this.b;
        return bArr[i] == 3 && bArr[i + (-2)] == 0 && bArr[i + (-1)] == 0;
    }

    public void s(int i) {
        int i2 = i / 8;
        this.c = i2;
        this.d = i - (i2 * 8);
        x();
    }

    public void t() {
        int i = this.d + 1;
        this.d = i;
        if (i == 8) {
            this.d = 0;
            this.c++;
        }
        x();
    }

    public void u(int i) {
        int i2 = i / 8;
        int i3 = this.c + i2;
        this.c = i3;
        int i4 = (i - (i2 * 8)) + this.d;
        this.d = i4;
        if (i4 > 7) {
            this.c = i3 + 1;
            this.d = i4 - 8;
        }
        x();
    }

    public void v(int i) {
        AbstractC1795We.L(this.d == 0);
        this.c += i;
        x();
    }

    public boolean w() {
        int i = this.b[this.c] & (128 >> this.d);
        t();
        return i != 0;
    }

    public void x() {
        int i;
        int i2 = this.c;
        boolean z = false;
        if (i2 >= 0 && (i2 < (i = this.e) || (i2 == i && this.d == 0))) {
            z = true;
        }
        AbstractC1795We.L(z);
    }

    public C2466p0() {
        this.a = 1;
        this.b = Yo.b;
    }

    public C2466p0(int i, byte[] bArr, int i2) {
        this.a = 2;
        this.b = bArr;
        this.d = i;
        this.c = i2;
        this.e = 0;
        p();
    }

    public C2466p0(byte[] bArr) {
        this.a = 0;
        this.b = bArr;
        this.c = bArr.length;
    }
}
