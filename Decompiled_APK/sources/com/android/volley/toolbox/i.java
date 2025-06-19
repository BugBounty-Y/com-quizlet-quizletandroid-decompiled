package com.android.volley.toolbox;

import com.google.android.gms.internal.ads.I3;
import java.io.ByteArrayOutputStream;

/* loaded from: classes.dex */
public final class i extends ByteArrayOutputStream implements AutoCloseable {
    public final /* synthetic */ int a = 0;
    public final Object b;

    public i(I3 i3, int i) {
        this.b = i3;
        ((ByteArrayOutputStream) this).buf = i3.j(Math.max(i, 256));
    }

    public void a(int i) {
        int i2 = ((ByteArrayOutputStream) this).count;
        if (i2 + i <= ((ByteArrayOutputStream) this).buf.length) {
            return;
        }
        int i3 = (i2 + i) * 2;
        a aVar = (a) this.b;
        byte[] bArrA = aVar.a(i3);
        System.arraycopy(((ByteArrayOutputStream) this).buf, 0, bArrA, 0, ((ByteArrayOutputStream) this).count);
        aVar.b(((ByteArrayOutputStream) this).buf);
        ((ByteArrayOutputStream) this).buf = bArrA;
    }

    @Override // java.io.ByteArrayOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        switch (this.a) {
            case 0:
                ((a) this.b).b(((ByteArrayOutputStream) this).buf);
                ((ByteArrayOutputStream) this).buf = null;
                super.close();
                break;
            default:
                ((I3) this.b).g(((ByteArrayOutputStream) this).buf);
                ((ByteArrayOutputStream) this).buf = null;
                super.close();
                break;
        }
    }

    public void d(int i) {
        int i2 = ((ByteArrayOutputStream) this).count;
        if (i2 + i <= ((ByteArrayOutputStream) this).buf.length) {
            return;
        }
        int i3 = i2 + i;
        I3 i32 = (I3) this.b;
        byte[] bArrJ = i32.j(i3 + i3);
        System.arraycopy(((ByteArrayOutputStream) this).buf, 0, bArrJ, 0, ((ByteArrayOutputStream) this).count);
        i32.g(((ByteArrayOutputStream) this).buf);
        ((ByteArrayOutputStream) this).buf = bArrJ;
    }

    public final void finalize() {
        switch (this.a) {
            case 0:
                ((a) this.b).b(((ByteArrayOutputStream) this).buf);
                break;
            default:
                ((I3) this.b).g(((ByteArrayOutputStream) this).buf);
                break;
        }
    }

    @Override // java.io.ByteArrayOutputStream, java.io.OutputStream
    public final synchronized void write(int i) {
        int i2 = this.a;
        synchronized (this) {
            switch (i2) {
                case 0:
                    a(1);
                    super.write(i);
                    return;
                default:
                    d(1);
                    super.write(i);
                    return;
            }
        }
    }

    public i(a aVar, int i) {
        this.b = aVar;
        ((ByteArrayOutputStream) this).buf = aVar.a(Math.max(i, 256));
    }

    @Override // java.io.ByteArrayOutputStream, java.io.OutputStream
    public final synchronized void write(byte[] bArr, int i, int i2) {
        int i3 = this.a;
        synchronized (this) {
            switch (i3) {
                case 0:
                    a(i2);
                    super.write(bArr, i, i2);
                    return;
                default:
                    d(i2);
                    super.write(bArr, i, i2);
                    return;
            }
        }
    }
}
