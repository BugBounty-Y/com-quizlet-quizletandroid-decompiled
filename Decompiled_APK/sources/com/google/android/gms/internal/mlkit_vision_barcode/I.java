package com.google.android.gms.internal.mlkit_vision_barcode;

import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class I extends OutputStream {
    public final /* synthetic */ int a;
    public long b;

    @Override // java.io.OutputStream
    public final void write(int i) {
        switch (this.a) {
            case 0:
                this.b++;
                break;
            case 1:
                this.b++;
                break;
            case 2:
                this.b++;
                break;
            case 3:
                this.b++;
                break;
            default:
                this.b++;
                break;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr) {
        switch (this.a) {
            case 0:
                this.b += bArr.length;
                break;
            case 1:
                this.b += bArr.length;
                break;
            case 2:
                this.b += bArr.length;
                break;
            case 3:
                this.b += bArr.length;
                break;
            default:
                this.b += bArr.length;
                break;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr, int i, int i2) {
        int length;
        int i3;
        int length2;
        int i4;
        int length3;
        int i5;
        int length4;
        int i6;
        int i7;
        switch (this.a) {
            case 0:
                if (i >= 0 && i <= (length = bArr.length) && i2 >= 0 && (i3 = i + i2) <= length && i3 >= 0) {
                    this.b += i2;
                    return;
                }
                throw new IndexOutOfBoundsException();
            case 1:
                if (i >= 0 && i <= (length2 = bArr.length) && i2 >= 0 && (i4 = i + i2) <= length2 && i4 >= 0) {
                    this.b += i2;
                    return;
                }
                throw new IndexOutOfBoundsException();
            case 2:
                if (i >= 0 && i <= (length3 = bArr.length) && i2 >= 0 && (i5 = i + i2) <= length3 && i5 >= 0) {
                    this.b += i2;
                    return;
                }
                throw new IndexOutOfBoundsException();
            case 3:
                if (i >= 0 && i <= (length4 = bArr.length) && i2 >= 0 && (i6 = i + i2) <= length4 && i6 >= 0) {
                    this.b += i2;
                    return;
                }
                throw new IndexOutOfBoundsException();
            default:
                if (i >= 0 && i <= bArr.length && i2 >= 0 && (i7 = i + i2) <= bArr.length && i7 >= 0) {
                    this.b += i2;
                    return;
                }
                throw new IndexOutOfBoundsException();
        }
    }
}
