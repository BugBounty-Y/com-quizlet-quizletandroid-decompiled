package com.google.firebase.perf.network;

import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.p;
import com.google.firebase.perf.v1.t;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;

/* loaded from: classes2.dex */
public final class e {
    public static final com.google.firebase.perf.logging.a f = com.google.firebase.perf.logging.a.d();
    public final HttpURLConnection a;
    public final com.google.firebase.perf.metrics.d b;
    public long c = -1;
    public long d = -1;
    public final Timer e;

    public e(HttpURLConnection httpURLConnection, Timer timer, com.google.firebase.perf.metrics.d dVar) {
        this.a = httpURLConnection;
        this.b = dVar;
        this.e = timer;
        dVar.l(httpURLConnection.getURL().toString());
    }

    public final void a() {
        long j = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        Timer timer = this.e;
        if (j == -1) {
            timer.c();
            long j2 = timer.a;
            this.c = j2;
            dVar.g(j2);
        }
        try {
            this.a.connect();
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final Object b() throws IOException {
        Timer timer = this.e;
        i();
        HttpURLConnection httpURLConnection = this.a;
        int responseCode = httpURLConnection.getResponseCode();
        com.google.firebase.perf.metrics.d dVar = this.b;
        dVar.d(responseCode);
        try {
            Object content = httpURLConnection.getContent();
            if (content instanceof InputStream) {
                dVar.h(httpURLConnection.getContentType());
                return new a((InputStream) content, dVar, timer);
            }
            dVar.h(httpURLConnection.getContentType());
            dVar.i(httpURLConnection.getContentLength());
            dVar.j(timer.a());
            dVar.b();
            return content;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final Object c(Class[] clsArr) throws IOException {
        Timer timer = this.e;
        i();
        HttpURLConnection httpURLConnection = this.a;
        int responseCode = httpURLConnection.getResponseCode();
        com.google.firebase.perf.metrics.d dVar = this.b;
        dVar.d(responseCode);
        try {
            Object content = httpURLConnection.getContent(clsArr);
            if (content instanceof InputStream) {
                dVar.h(httpURLConnection.getContentType());
                return new a((InputStream) content, dVar, timer);
            }
            dVar.h(httpURLConnection.getContentType());
            dVar.i(httpURLConnection.getContentLength());
            dVar.j(timer.a());
            dVar.b();
            return content;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final InputStream d() {
        HttpURLConnection httpURLConnection = this.a;
        com.google.firebase.perf.metrics.d dVar = this.b;
        i();
        try {
            dVar.d(httpURLConnection.getResponseCode());
        } catch (IOException unused) {
            f.a();
        }
        InputStream errorStream = httpURLConnection.getErrorStream();
        return errorStream != null ? new a(errorStream, dVar, this.e) : errorStream;
    }

    public final InputStream e() throws IOException {
        Timer timer = this.e;
        i();
        HttpURLConnection httpURLConnection = this.a;
        int responseCode = httpURLConnection.getResponseCode();
        com.google.firebase.perf.metrics.d dVar = this.b;
        dVar.d(responseCode);
        dVar.h(httpURLConnection.getContentType());
        try {
            InputStream inputStream = httpURLConnection.getInputStream();
            return inputStream != null ? new a(inputStream, dVar, timer) : inputStream;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final boolean equals(Object obj) {
        return this.a.equals(obj);
    }

    public final OutputStream f() throws IOException {
        Timer timer = this.e;
        com.google.firebase.perf.metrics.d dVar = this.b;
        try {
            OutputStream outputStream = this.a.getOutputStream();
            return outputStream != null ? new b(outputStream, dVar, timer) : outputStream;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final int g() throws IOException {
        i();
        long j = this.d;
        Timer timer = this.e;
        com.google.firebase.perf.metrics.d dVar = this.b;
        if (j == -1) {
            long jA = timer.a();
            this.d = jA;
            p pVar = dVar.d;
            pVar.k();
            t.D((t) pVar.b, jA);
        }
        try {
            int responseCode = this.a.getResponseCode();
            dVar.d(responseCode);
            return responseCode;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final String h() throws IOException {
        HttpURLConnection httpURLConnection = this.a;
        i();
        long j = this.d;
        Timer timer = this.e;
        com.google.firebase.perf.metrics.d dVar = this.b;
        if (j == -1) {
            long jA = timer.a();
            this.d = jA;
            p pVar = dVar.d;
            pVar.k();
            t.D((t) pVar.b, jA);
        }
        try {
            String responseMessage = httpURLConnection.getResponseMessage();
            dVar.d(httpURLConnection.getResponseCode());
            return responseMessage;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final void i() {
        long j = this.c;
        com.google.firebase.perf.metrics.d dVar = this.b;
        if (j == -1) {
            Timer timer = this.e;
            timer.c();
            long j2 = timer.a;
            this.c = j2;
            dVar.g(j2);
        }
        HttpURLConnection httpURLConnection = this.a;
        String requestMethod = httpURLConnection.getRequestMethod();
        if (requestMethod != null) {
            dVar.c(requestMethod);
        } else if (httpURLConnection.getDoOutput()) {
            dVar.c("POST");
        } else {
            dVar.c("GET");
        }
    }

    public final String toString() {
        return this.a.toString();
    }
}
