package com.google.android.gms.internal.ads;

import android.content.Context;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2;
import java.io.EOFException;
import java.io.IOException;
import java.net.Proxy;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.ea, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2007ea implements okhttp3.internal.http.d {
    public Object a;
    public int b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;

    public C2007ea(okhttp3.A a, okhttp3.internal.connection.i connection, okio.A source, okio.z sink) {
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(sink, "sink");
        this.c = a;
        this.d = connection;
        this.a = source;
        this.e = sink;
        this.f = new androidx.compose.foundation.gestures.l1(source);
    }

    public static final void i(C2007ea c2007ea, okio.p pVar) {
        c2007ea.getClass();
        okio.I i = pVar.e;
        okio.H delegate = okio.I.d;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        pVar.e = delegate;
        i.a();
        i.b();
    }

    @Override // okhttp3.internal.http.d
    public void a() {
        ((okio.z) this.e).flush();
    }

    @Override // okhttp3.internal.http.d
    public void b(okhttp3.C request) {
        Intrinsics.checkNotNullParameter(request, "request");
        Proxy.Type proxyType = ((okhttp3.internal.connection.i) this.d).b.b.type();
        Intrinsics.checkNotNullExpressionValue(proxyType, "connection.route().proxy.type()");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(proxyType, "proxyType");
        StringBuilder sb = new StringBuilder();
        sb.append(request.b);
        sb.append(' ');
        okhttp3.s url = request.a;
        if (url.j || proxyType != Proxy.Type.HTTP) {
            Intrinsics.checkNotNullParameter(url, "url");
            String strB = url.b();
            String strD = url.d();
            if (strD != null) {
                strB = strB + '?' + strD;
            }
            sb.append(strB);
        } else {
            sb.append(url);
        }
        sb.append(" HTTP/1.1");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        m(request.c, string);
    }

    @Override // okhttp3.internal.http.d
    public okio.G c(okhttp3.H response) {
        Intrinsics.checkNotNullParameter(response, "response");
        if (!okhttp3.internal.http.e.a(response)) {
            return l(0L);
        }
        if ("chunked".equalsIgnoreCase(okhttp3.H.a("Transfer-Encoding", response))) {
            okhttp3.s sVar = response.a.a;
            if (this.b == 4) {
                this.b = 5;
                return new okhttp3.internal.http1.c(this, sVar);
            }
            throw new IllegalStateException(("state: " + this.b).toString());
        }
        long jL = okhttp3.internal.b.l(response);
        if (jL != -1) {
            return l(jL);
        }
        if (this.b == 4) {
            this.b = 5;
            ((okhttp3.internal.connection.i) this.d).k();
            return new okhttp3.internal.http1.e(this);
        }
        throw new IllegalStateException(("state: " + this.b).toString());
    }

    @Override // okhttp3.internal.http.d
    public void cancel() {
        Socket socket = ((okhttp3.internal.connection.i) this.d).c;
        if (socket != null) {
            okhttp3.internal.b.e(socket);
        }
    }

    @Override // okhttp3.internal.http.d
    public okhttp3.G d(boolean z) throws IOException {
        androidx.compose.foundation.gestures.l1 l1Var = (androidx.compose.foundation.gestures.l1) this.f;
        int i = this.b;
        if (i != 1 && i != 2 && i != 3) {
            throw new IllegalStateException(("state: " + this.b).toString());
        }
        try {
            String strY = ((okio.A) l1Var.c).y(l1Var.b);
            l1Var.b -= strY.length();
            C0122z c0122zB = AbstractC3371n2.b(strY);
            int i2 = c0122zB.b;
            okhttp3.G g = new okhttp3.G();
            okhttp3.B protocol = (okhttp3.B) c0122zB.c;
            Intrinsics.checkNotNullParameter(protocol, "protocol");
            g.b = protocol;
            g.c = i2;
            String message = (String) c0122zB.d;
            Intrinsics.checkNotNullParameter(message, "message");
            g.d = message;
            okhttp3.r headers = l1Var.E();
            Intrinsics.checkNotNullParameter(headers, "headers");
            g.f = headers.e();
            if (z && i2 == 100) {
                return null;
            }
            if (i2 == 100) {
                this.b = 3;
                return g;
            }
            if (102 > i2 || i2 >= 200) {
                this.b = 4;
                return g;
            }
            this.b = 3;
            return g;
        } catch (EOFException e) {
            throw new IOException(AbstractC0147y.d("unexpected end of stream on ", ((okhttp3.internal.connection.i) this.d).b.a.h.h()), e);
        }
    }

    @Override // okhttp3.internal.http.d
    public okhttp3.internal.connection.i e() {
        return (okhttp3.internal.connection.i) this.d;
    }

    @Override // okhttp3.internal.http.d
    public void f() {
        ((okio.z) this.e).flush();
    }

    @Override // okhttp3.internal.http.d
    public long g(okhttp3.H response) {
        Intrinsics.checkNotNullParameter(response, "response");
        if (!okhttp3.internal.http.e.a(response)) {
            return 0L;
        }
        if ("chunked".equalsIgnoreCase(okhttp3.H.a("Transfer-Encoding", response))) {
            return -1L;
        }
        return okhttp3.internal.b.l(response);
    }

    @Override // okhttp3.internal.http.d
    public okio.E h(okhttp3.C request, long j) {
        Intrinsics.checkNotNullParameter(request, "request");
        okhttp3.F f = request.d;
        if ("chunked".equalsIgnoreCase(request.a("Transfer-Encoding"))) {
            if (this.b == 1) {
                this.b = 2;
                return new okhttp3.internal.http1.b(this);
            }
            throw new IllegalStateException(("state: " + this.b).toString());
        }
        if (j == -1) {
            throw new IllegalStateException("Cannot stream a request body without chunked encoding or a known content length!");
        }
        if (this.b == 1) {
            this.b = 2;
            return new coil3.disk.f(this);
        }
        throw new IllegalStateException(("state: " + this.b).toString());
    }

    public com.google.firebase.installations.local.a j() {
        String strK = this.b == 0 ? " registrationStatus" : "";
        if (((Long) this.e) == null) {
            strK = strK.concat(" expiresInSecs");
        }
        if (((Long) this.f) == null) {
            strK = android.support.v4.media.session.a.k(strK, " tokenCreationEpochInSecs");
        }
        if (strK.isEmpty()) {
            return new com.google.firebase.installations.local.a((String) this.a, this.b, (String) this.c, (String) this.d, ((Long) this.e).longValue(), ((Long) this.f).longValue(), (String) this.g);
        }
        throw new IllegalStateException("Missing required properties:".concat(strK));
    }

    public boolean k() {
        return this.b < ((List) this.f).size() || !((ArrayList) this.g).isEmpty();
    }

    public okhttp3.internal.http1.d l(long j) {
        if (this.b == 4) {
            this.b = 5;
            return new okhttp3.internal.http1.d(this, j);
        }
        throw new IllegalStateException(("state: " + this.b).toString());
    }

    public void m(okhttp3.r headers, String requestLine) {
        Intrinsics.checkNotNullParameter(headers, "headers");
        Intrinsics.checkNotNullParameter(requestLine, "requestLine");
        if (this.b != 0) {
            throw new IllegalStateException(("state: " + this.b).toString());
        }
        okio.z zVar = (okio.z) this.e;
        zVar.H(requestLine);
        zVar.H("\r\n");
        int size = headers.size();
        for (int i = 0; i < size; i++) {
            zVar.H(headers.b(i));
            zVar.H(": ");
            zVar.H(headers.g(i));
            zVar.H("\r\n");
        }
        zVar.H("\r\n");
        this.b = 1;
    }

    public C1920ca n() {
        com.google.android.gms.ads.internal.util.A.l("getEngine: Trying to acquire lock");
        Object obj = this.c;
        synchronized (obj) {
            try {
                com.google.android.gms.ads.internal.util.A.l("getEngine: Lock acquired");
                com.google.android.gms.ads.internal.util.A.l("refreshIfDestroyed: Trying to acquire lock");
                synchronized (obj) {
                    try {
                        com.google.android.gms.ads.internal.util.A.l("refreshIfDestroyed: Lock acquired");
                        C1964da c1964da = (C1964da) this.g;
                        if (c1964da != null && this.b == 0) {
                            c1964da.u(new Ts(this, 8), new L9(2));
                        }
                    } finally {
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.util.A.l("refreshIfDestroyed: Lock released");
        C1964da c1964da2 = (C1964da) this.g;
        if (c1964da2 != null && ((AtomicInteger) c1964da2.c).get() != -1) {
            int i = this.b;
            if (i == 0) {
                com.google.android.gms.ads.internal.util.A.l("getEngine (NO_UPDATE): Lock released");
                return ((C1964da) this.g).v();
            }
            if (i != 1) {
                com.google.android.gms.ads.internal.util.A.l("getEngine (UPDATING): Lock released");
                return ((C1964da) this.g).v();
            }
            this.b = 2;
            o();
            com.google.android.gms.ads.internal.util.A.l("getEngine (PENDING_UPDATE): Lock released");
            return ((C1964da) this.g).v();
        }
        this.b = 2;
        this.g = o();
        com.google.android.gms.ads.internal.util.A.l("getEngine (NULL or REJECTED): Lock released");
        return ((C1964da) this.g).v();
    }

    public C1964da o() {
        Pq pqF = LA.f((Context) this.d, 6);
        pqF.zzi();
        C1964da c1964da = new C1964da();
        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before UI_THREAD_EXECUTOR");
        AbstractC2270kd.f.execute(new Qv(7, this, c1964da));
        com.google.android.gms.ads.internal.util.A.l("loadNewJavascriptEngine: Promise created");
        c1964da.u(new C1877ba(this, c1964da, pqF), new C1877ba(this, c1964da, pqF));
        return c1964da;
    }
}
