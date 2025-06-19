package com.android.volley.toolbox;

import com.google.android.gms.internal.ads.AbstractC1981ds;
import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes.dex */
public final class c extends FilterInputStream {
    public final /* synthetic */ int a;
    public long b;
    public long c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(BufferedInputStream bufferedInputStream, long j, int i) {
        super(bufferedInputStream);
        this.a = i;
        this.b = j;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int available() {
        switch (this.a) {
            case 2:
                return (int) Math.min(((FilterInputStream) this).in.available(), this.b);
            case 3:
                return (int) Math.min(((FilterInputStream) this).in.available(), this.b);
            default:
                return super.available();
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void mark(int i) {
        switch (this.a) {
            case 2:
                synchronized (this) {
                    ((FilterInputStream) this).in.mark(i);
                    this.c = this.b;
                }
                return;
            case 3:
                synchronized (this) {
                    ((FilterInputStream) this).in.mark(i);
                    this.c = this.b;
                }
                return;
            default:
                super.mark(i);
                return;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final int read() throws IOException {
        switch (this.a) {
            case 0:
                int i = super.read();
                if (i != -1) {
                    this.c++;
                }
                return i;
            case 1:
                int i2 = super.read();
                if (i2 != -1) {
                    this.c++;
                }
                return i2;
            case 2:
                if (this.b == 0) {
                    return -1;
                }
                int i3 = ((FilterInputStream) this).in.read();
                if (i3 != -1) {
                    this.b--;
                }
                return i3;
            default:
                if (this.b == 0) {
                    return -1;
                }
                int i4 = ((FilterInputStream) this).in.read();
                if (i4 != -1) {
                    this.b--;
                }
                return i4;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public synchronized void reset() throws IOException {
        switch (this.a) {
            case 2:
                synchronized (this) {
                    if (!((FilterInputStream) this).in.markSupported()) {
                        throw new IOException("Mark not supported");
                    }
                    if (this.c == -1) {
                        throw new IOException("Mark not set");
                    }
                    ((FilterInputStream) this).in.reset();
                    this.b = this.c;
                }
                return;
            case 3:
                synchronized (this) {
                    if (!((FilterInputStream) this).in.markSupported()) {
                        throw new IOException("Mark not supported");
                    }
                    if (this.c == -1) {
                        throw new IOException("Mark not set");
                    }
                    ((FilterInputStream) this).in.reset();
                    this.b = this.c;
                }
                return;
            default:
                super.reset();
                return;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public long skip(long j) throws IOException {
        switch (this.a) {
            case 2:
                long jSkip = ((FilterInputStream) this).in.skip(Math.min(j, this.b));
                this.b -= jSkip;
                return jSkip;
            case 3:
                long jSkip2 = ((FilterInputStream) this).in.skip(Math.min(j, this.b));
                this.b -= jSkip2;
                return jSkip2;
            default:
                return super.skip(j);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(InputStream inputStream, long j) {
        super(inputStream);
        this.a = 2;
        this.c = -1L;
        inputStream.getClass();
        AbstractC1981ds.E("limit must be non-negative", j >= 0);
        this.b = j;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(InputStream inputStream) {
        super(inputStream);
        this.a = 3;
        this.c = -1L;
        this.b = 1048577L;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public final int read(byte[] bArr, int i, int i2) throws IOException {
        switch (this.a) {
            case 0:
                int i3 = super.read(bArr, i, i2);
                if (i3 != -1) {
                    this.c += i3;
                }
                return i3;
            case 1:
                int i4 = super.read(bArr, i, i2);
                if (i4 != -1) {
                    this.c += i4;
                }
                return i4;
            case 2:
                long j = this.b;
                if (j == 0) {
                    return -1;
                }
                int i5 = ((FilterInputStream) this).in.read(bArr, i, (int) Math.min(i2, j));
                if (i5 != -1) {
                    this.b -= i5;
                }
                return i5;
            default:
                long j2 = this.b;
                if (j2 == 0) {
                    return -1;
                }
                int i6 = ((FilterInputStream) this).in.read(bArr, i, (int) Math.min(i2, j2));
                if (i6 != -1) {
                    this.b -= i6;
                }
                return i6;
        }
    }
}
