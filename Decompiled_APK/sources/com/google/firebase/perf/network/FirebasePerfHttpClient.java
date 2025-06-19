package com.google.firebase.perf.network;

import androidx.annotation.Keep;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.util.Timer;
import java.io.IOException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;

/* loaded from: classes2.dex */
public class FirebasePerfHttpClient {
    @Keep
    public static HttpResponse execute(HttpClient httpClient, HttpUriRequest httpUriRequest) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpUriRequest.getURI().toString());
            dVar.c(httpUriRequest.getMethod());
            Long lA = g.a(httpUriRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            HttpResponse httpResponseExecute = httpClient.execute(httpUriRequest);
            dVar.j(timer.a());
            dVar.d(httpResponseExecute.getStatusLine().getStatusCode());
            Long lA2 = g.a(httpResponseExecute);
            if (lA2 != null) {
                dVar.i(lA2.longValue());
            }
            String strB = g.b(httpResponseExecute);
            if (strB != null) {
                dVar.h(strB);
            }
            dVar.b();
            return httpResponseExecute;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static HttpResponse execute(HttpClient httpClient, HttpUriRequest httpUriRequest, HttpContext httpContext) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpUriRequest.getURI().toString());
            dVar.c(httpUriRequest.getMethod());
            Long lA = g.a(httpUriRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            HttpResponse httpResponseExecute = httpClient.execute(httpUriRequest, httpContext);
            dVar.j(timer.a());
            dVar.d(httpResponseExecute.getStatusLine().getStatusCode());
            Long lA2 = g.a(httpResponseExecute);
            if (lA2 != null) {
                dVar.i(lA2.longValue());
            }
            String strB = g.b(httpResponseExecute);
            if (strB != null) {
                dVar.h(strB);
            }
            dVar.b();
            return httpResponseExecute;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static <T> T execute(HttpClient httpClient, HttpUriRequest httpUriRequest, ResponseHandler<T> responseHandler) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpUriRequest.getURI().toString());
            dVar.c(httpUriRequest.getMethod());
            Long lA = g.a(httpUriRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            return (T) httpClient.execute(httpUriRequest, new f(responseHandler, timer, dVar));
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static <T> T execute(HttpClient httpClient, HttpUriRequest httpUriRequest, ResponseHandler<T> responseHandler, HttpContext httpContext) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpUriRequest.getURI().toString());
            dVar.c(httpUriRequest.getMethod());
            Long lA = g.a(httpUriRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            return (T) httpClient.execute(httpUriRequest, new f(responseHandler, timer, dVar), httpContext);
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static HttpResponse execute(HttpClient httpClient, HttpHost httpHost, HttpRequest httpRequest) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpHost.toURI() + httpRequest.getRequestLine().getUri());
            dVar.c(httpRequest.getRequestLine().getMethod());
            Long lA = g.a(httpRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            HttpResponse httpResponseExecute = httpClient.execute(httpHost, httpRequest);
            dVar.j(timer.a());
            dVar.d(httpResponseExecute.getStatusLine().getStatusCode());
            Long lA2 = g.a(httpResponseExecute);
            if (lA2 != null) {
                dVar.i(lA2.longValue());
            }
            String strB = g.b(httpResponseExecute);
            if (strB != null) {
                dVar.h(strB);
            }
            dVar.b();
            return httpResponseExecute;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static HttpResponse execute(HttpClient httpClient, HttpHost httpHost, HttpRequest httpRequest, HttpContext httpContext) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpHost.toURI() + httpRequest.getRequestLine().getUri());
            dVar.c(httpRequest.getRequestLine().getMethod());
            Long lA = g.a(httpRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            HttpResponse httpResponseExecute = httpClient.execute(httpHost, httpRequest, httpContext);
            dVar.j(timer.a());
            dVar.d(httpResponseExecute.getStatusLine().getStatusCode());
            Long lA2 = g.a(httpResponseExecute);
            if (lA2 != null) {
                dVar.i(lA2.longValue());
            }
            String strB = g.b(httpResponseExecute);
            if (strB != null) {
                dVar.h(strB);
            }
            dVar.b();
            return httpResponseExecute;
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static <T> T execute(HttpClient httpClient, HttpHost httpHost, HttpRequest httpRequest, ResponseHandler<? extends T> responseHandler) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpHost.toURI() + httpRequest.getRequestLine().getUri());
            dVar.c(httpRequest.getRequestLine().getMethod());
            Long lA = g.a(httpRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            return (T) httpClient.execute(httpHost, httpRequest, new f(responseHandler, timer, dVar));
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }

    @Keep
    public static <T> T execute(HttpClient httpClient, HttpHost httpHost, HttpRequest httpRequest, ResponseHandler<? extends T> responseHandler, HttpContext httpContext) throws IOException {
        Timer timer = new Timer();
        com.google.firebase.perf.metrics.d dVar = new com.google.firebase.perf.metrics.d(com.google.firebase.perf.transport.f.s);
        try {
            dVar.l(httpHost.toURI() + httpRequest.getRequestLine().getUri());
            dVar.c(httpRequest.getRequestLine().getMethod());
            Long lA = g.a(httpRequest);
            if (lA != null) {
                dVar.f(lA.longValue());
            }
            timer.c();
            dVar.g(timer.a);
            return (T) httpClient.execute(httpHost, httpRequest, new f(responseHandler, timer, dVar), httpContext);
        } catch (IOException e) {
            Z.m(timer, dVar, dVar);
            throw e;
        }
    }
}
