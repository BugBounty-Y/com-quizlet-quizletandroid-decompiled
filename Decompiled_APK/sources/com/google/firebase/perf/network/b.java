package com.google.firebase.perf.network;

import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.p;
import com.google.firebase.perf.v1.t;
import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class b extends OutputStream implements AutoCloseable {
    public final OutputStream a;
    public final Timer b;
    public final com.google.firebase.perf.metrics.d c;
    public long d = -1;

    public b(OutputStream outputStream, com.google.firebase.perf.metrics.d dVar, Timer timer) {
        this.a = outputStream;
        this.c = dVar;
        this.b = timer;
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        long j = this.d;
        com.google.firebase.perf.metrics.d dVar = this.c;
        if (j != -1) {
            dVar.f(j);
        }
        Timer timer = this.b;
        long jA = timer.a();
        p pVar = dVar.d;
        pVar.k();
        t.C((t) pVar.b, jA);
        try {
            this.a.close();
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public final void flush() throws IOException {
        try {
            this.a.flush();
        } catch (IOException e) {
            long jA = this.b.a();
            com.google.firebase.perf.metrics.d dVar = this.c;
            dVar.j(jA);
            g.c(dVar);
            throw e;
        }
    }

    @Override // java.io.OutputStream
    public final void write(int i) throws IOException {
        com.google.firebase.perf.metrics.d dVar = this.c;
        try {
            this.a.write(i);
            long j = this.d + 1;
            this.d = j;
            dVar.f(j);
        } catch (IOException e) {
            Z.m(this.b, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr) throws IOException {
        com.google.firebase.perf.metrics.d dVar = this.c;
        try {
            this.a.write(bArr);
            long length = this.d + bArr.length;
            this.d = length;
            dVar.f(length);
        } catch (IOException e) {
            Z.m(this.b, dVar, dVar);
            throw e;
        }
    }

    @Override // java.io.OutputStream
    public final void write(byte[] bArr, int i, int i2) throws IOException {
        com.google.firebase.perf.metrics.d dVar = this.c;
        try {
            this.a.write(bArr, i, i2);
            long j = this.d + i2;
            this.d = j;
            dVar.f(j);
        } catch (IOException e) {
            Z.m(this.b, dVar, dVar);
            throw e;
        }
    }
}
