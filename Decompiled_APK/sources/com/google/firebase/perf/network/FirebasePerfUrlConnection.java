package com.google.firebase.perf.network;

import androidx.annotation.Keep;
import com.google.firebase.perf.util.Timer;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.HttpsURLConnection;

/* loaded from: classes2.dex */
public class FirebasePerfUrlConnection {
    @Keep
    public static Object getContent(URL url) throws IOException {
        com.google.firebase.perf.transport.f fVar = com.google.firebase.perf.transport.f.s;
        Timer timer = new Timer();
        timer.c();
        long j = timer.a;
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(fVar);
        try {
            URLConnection uRLConnectionOpenConnection = url.openConnection();
            return uRLConnectionOpenConnection instanceof HttpsURLConnection ? new d((HttpsURLConnection) uRLConnectionOpenConnection, timer, dVar).a.b() : uRLConnectionOpenConnection instanceof HttpURLConnection ? new c((HttpURLConnection) uRLConnectionOpenConnection, timer, dVar).a.b() : uRLConnectionOpenConnection.getContent();
        } catch (IOException e) {
            dVar.g(j);
            dVar.j(timer.a());
            dVar.l(url.toString());
            g.c(dVar);
            throw e;
        }
    }

    @Keep
    public static Object instrument(Object obj) throws IOException {
        return obj instanceof HttpsURLConnection ? new d((HttpsURLConnection) obj, new Timer(), new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s)) : obj instanceof HttpURLConnection ? new c((HttpURLConnection) obj, new Timer(), new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s)) : obj;
    }

    @Keep
    public static InputStream openStream(URL url) throws IOException {
        com.google.firebase.perf.transport.f fVar = com.google.firebase.perf.transport.f.s;
        Timer timer = new Timer();
        if (!fVar.c.get()) {
            return url.openConnection().getInputStream();
        }
        timer.c();
        long j = timer.a;
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(fVar);
        try {
            URLConnection uRLConnectionOpenConnection = url.openConnection();
            return uRLConnectionOpenConnection instanceof HttpsURLConnection ? new d((HttpsURLConnection) uRLConnectionOpenConnection, timer, dVar).a.e() : uRLConnectionOpenConnection instanceof HttpURLConnection ? new c((HttpURLConnection) uRLConnectionOpenConnection, timer, dVar).a.e() : uRLConnectionOpenConnection.getInputStream();
        } catch (IOException e) {
            dVar.g(j);
            dVar.j(timer.a());
            dVar.l(url.toString());
            g.c(dVar);
            throw e;
        }
    }

    @Keep
    public static Object getContent(URL url, Class[] clsArr) throws IOException {
        com.google.firebase.perf.transport.f fVar = com.google.firebase.perf.transport.f.s;
        Timer timer = new Timer();
        timer.c();
        long j = timer.a;
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(fVar);
        try {
            URLConnection uRLConnectionOpenConnection = url.openConnection();
            if (uRLConnectionOpenConnection instanceof HttpsURLConnection) {
                return new d((HttpsURLConnection) uRLConnectionOpenConnection, timer, dVar).a.c(clsArr);
            }
            if (uRLConnectionOpenConnection instanceof HttpURLConnection) {
                return new c((HttpURLConnection) uRLConnectionOpenConnection, timer, dVar).a.c(clsArr);
            }
            return uRLConnectionOpenConnection.getContent(clsArr);
        } catch (IOException e) {
            dVar.g(j);
            dVar.j(timer.a());
            dVar.l(url.toString());
            g.c(dVar);
            throw e;
        }
    }
}
