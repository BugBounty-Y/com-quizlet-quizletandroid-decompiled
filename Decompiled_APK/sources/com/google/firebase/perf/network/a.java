package com.google.firebase.perf.network;

import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.p;
import com.google.firebase.perf.v1.t;
import java.io.IOException;
import java.io.InputStream;

/* loaded from: classes2.dex */
public final class a extends InputStream implements AutoCloseable {
    public final InputStream a;
    public final com.google.firebase.perf.metrics.d b;
    public final Timer c;
    public long e;
    public long d = -1;
    public long f = -1;

    public a(InputStream inputStream, com.google.firebase.perf.metrics.d dVar, Timer timer) {
        this.c = timer;
        this.a = inputStream;
        this.b = dVar;
        this.e = ((t) dVar.d.b).S();
    }

    public final void a(long j) {
        long j2 = this.d;
        if (j2 == -1) {
            this.d = j;
        } else {
            this.d = j2 + j;
        }
    }

    @Override // java.io.InputStream
    public final int available() throws IOException {
        try {
            return this.a.available();
        } catch (IOException e) {
            long jA = this.c.a();
            com.google.firebase.perf.metrics.d dVar = this.b;
            dVar.j(jA);
            g.c(dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        com.google.firebase.perf.metrics.d dVar = this.b;
        Timer timer = this.c;
        long jA = timer.a();
        if (this.f == -1) {
            this.f = jA;
        }
        try {
            this.a.close();
            long j = this.d;
            if (j != -1) {
                dVar.i(j);
            }
            long j2 = this.e;
            if (j2 != -1) {
                p pVar = dVar.d;
                pVar.k();
                t.D((t) pVar.b, j2);
            }
            dVar.j(this.f);
            dVar.b();
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream
    public final void mark(int i) {
        this.a.mark(i);
    }

    @Override // java.io.InputStream
    public final boolean markSupported() {
        return this.a.markSupported();
    }

    @Override // java.io.InputStream
    public final int read() throws IOException {
        Timer timer = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        try {
            int i = this.a.read();
            long jA = timer.a();
            if (this.e == -1) {
                this.e = jA;
            }
            if (i != -1 || this.f != -1) {
                a(1L);
                dVar.i(this.d);
                return i;
            }
            this.f = jA;
            dVar.j(jA);
            dVar.b();
            return i;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream
    public final void reset() throws IOException {
        try {
            this.a.reset();
        } catch (IOException e) {
            long jA = this.c.a();
            com.google.firebase.perf.metrics.d dVar = this.b;
            dVar.j(jA);
            g.c(dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream
    public final long skip(long j) throws IOException {
        Timer timer = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        try {
            long jSkip = this.a.skip(j);
            long jA = timer.a();
            if (this.e == -1) {
                this.e = jA;
            }
            if (jSkip == 0 && j != 0 && this.f == -1) {
                this.f = jA;
                dVar.j(jA);
                return jSkip;
            }
            a(jSkip);
            dVar.i(this.d);
            return jSkip;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream
    public final int read(byte[] bArr, int i, int i2) throws IOException {
        Timer timer = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        try {
            int i3 = this.a.read(bArr, i, i2);
            long jA = timer.a();
            if (this.e == -1) {
                this.e = jA;
            }
            if (i3 == -1 && this.f == -1) {
                this.f = jA;
                dVar.j(jA);
                dVar.b();
                return i3;
            }
            a(i3);
            dVar.i(this.d);
            return i3;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.InputStream
    public final int read(byte[] bArr) throws IOException {
        Timer timer = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        try {
            int i = this.a.read(bArr);
            long jA = timer.a();
            if (this.e == -1) {
                this.e = jA;
            }
            if (i == -1 && this.f == -1) {
                this.f = jA;
                dVar.j(jA);
                dVar.b();
                return i;
            }
            a(i);
            dVar.i(this.d);
            return i;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }
}
