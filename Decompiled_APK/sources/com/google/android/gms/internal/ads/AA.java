package com.google.android.gms.internal.ads;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class AA extends OutputStream {
    public static final byte[] f = new byte[0];
    public int c;
    public int e;
    public final int a = 128;
    public final ArrayList b = new ArrayList();
    public byte[] d = new byte[128];

    public final synchronized BA a() {
        try {
            int i = this.e;
            byte[] bArr = this.d;
            if (i >= bArr.length) {
                this.b.add(new C2905zA(this.d));
                this.d = f;
            } else if (i > 0) {
                this.b.add(new C2905zA(Arrays.copyOf(bArr, i)));
            }
            this.c += this.e;
            this.e = 0;
        } catch (Throwable th) {
            throw th;
        }
        return BA.v(this.b);
    }

    public final void d(int i) {
        this.b.add(new C2905zA(this.d));
        int length = this.c + this.d.length;
        this.c = length;
        this.d = new byte[Math.max(this.a, Math.max(i, length >>> 1))];
        this.e = 0;
    }

    public final String toString() {
        int i;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        synchronized (this) {
            i = this.c + this.e;
        }
        return String.format("<ByteString.Output@%s size=%d>", hexString, Integer.valueOf(i));
    }

    @Override // java.io.OutputStream
    public final synchronized void write(int i) {
        try {
            if (this.e == this.d.length) {
                d(1);
            }
            byte[] bArr = this.d;
            int i2 = this.e;
            this.e = i2 + 1;
            bArr[i2] = (byte) i;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // java.io.OutputStream
    public final synchronized void write(byte[] bArr, int i, int i2) {
        byte[] bArr2 = this.d;
        int length = bArr2.length;
        int i3 = this.e;
        int i4 = length - i3;
        if (i2 <= i4) {
            System.arraycopy(bArr, i, bArr2, i3, i2);
            this.e += i2;
            return;
        }
        System.arraycopy(bArr, i, bArr2, i3, i4);
        int i5 = i2 - i4;
        d(i5);
        System.arraycopy(bArr, i + i4, this.d, 0, i5);
        this.e = i5;
    }
}
