package okhttp3.internal.connection;

import androidx.camera.camera2.internal.c0;
import androidx.compose.foundation.C0473q;
import com.comscore.android.id.IdHelperAndroid;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.C1719Ka;
import com.google.android.gms.internal.ads.C2007ea;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3331d2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3339f2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownServiceException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import kotlin.C4937f;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import okhttp3.B;
import okhttp3.C;
import okhttp3.C5072a;
import okhttp3.C5079h;
import okhttp3.C5082k;
import okhttp3.G;
import okhttp3.H;
import okhttp3.I;
import okhttp3.InterfaceC5076e;
import okhttp3.K;
import okhttp3.internal.http2.n;
import okhttp3.internal.http2.v;
import okhttp3.internal.http2.w;
import okhttp3.o;
import okhttp3.q;
import okhttp3.s;
import okio.A;
import okio.AbstractC5085b;
import okio.z;

/* loaded from: classes3.dex */
public final class i extends okhttp3.internal.http2.g {
    public final K b;
    public Socket c;
    public Socket d;
    public q e;
    public B f;
    public n g;
    public A h;
    public z i;
    public boolean j;
    public boolean k;
    public int l;
    public int m;
    public int n;
    public int o;
    public final ArrayList p;
    public long q;

    public i(J connectionPool, K route) {
        Intrinsics.checkNotNullParameter(connectionPool, "connectionPool");
        Intrinsics.checkNotNullParameter(route, "route");
        this.b = route;
        this.o = 1;
        this.p = new ArrayList();
        this.q = Long.MAX_VALUE;
    }

    public static void d(okhttp3.A client, K failedRoute, IOException failure) {
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(failedRoute, "failedRoute");
        Intrinsics.checkNotNullParameter(failure, "failure");
        if (failedRoute.b.type() != Proxy.Type.DIRECT) {
            C5072a c5072a = failedRoute.a;
            c5072a.g.connectFailed(c5072a.h.j(), failedRoute.b.address(), failure);
        }
        com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = client.z;
        synchronized (nVar) {
            Intrinsics.checkNotNullParameter(failedRoute, "failedRoute");
            ((LinkedHashSet) nVar.b).add(failedRoute);
        }
    }

    @Override // okhttp3.internal.http2.g
    public final synchronized void a(n connection, okhttp3.internal.http2.z settings) {
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(settings, "settings");
        this.o = (settings.a & 16) != 0 ? settings.b[4] : SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    @Override // okhttp3.internal.http2.g
    public final void b(v stream) {
        Intrinsics.checkNotNullParameter(stream, "stream");
        stream.c(okhttp3.internal.http2.a.REFUSED_STREAM, null);
    }

    public final void c(int i, int i2, int i3, boolean z, InterfaceC5076e call) throws Throwable {
        K k;
        o eventListener = o.c;
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(eventListener, "eventListener");
        if (this.f != null) {
            throw new IllegalStateException("already connected");
        }
        List list = this.b.a.j;
        C1719Ka c1719Ka = new C1719Ka(list);
        C5072a c5072a = this.b.a;
        if (c5072a.c == null) {
            if (!list.contains(C5082k.f)) {
                throw new RouteException(new UnknownServiceException("CLEARTEXT communication not enabled for client"));
            }
            String str = this.b.a.h.d;
            okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
            if (!okhttp3.internal.platform.o.a.h(str)) {
                throw new RouteException(new UnknownServiceException(android.support.v4.media.session.a.B("CLEARTEXT communication to ", str, " not permitted by network security policy")));
            }
        } else if (c5072a.i.contains(B.H2_PRIOR_KNOWLEDGE)) {
            throw new RouteException(new UnknownServiceException("H2_PRIOR_KNOWLEDGE cannot be used with HTTPS"));
        }
        RouteException routeException = null;
        do {
            try {
                K k2 = this.b;
                if (k2.a.c != null && k2.b.type() == Proxy.Type.HTTP) {
                    f(i, i2, i3, call);
                    if (this.c == null) {
                    }
                    k = this.b;
                    if (k.a.c == null && k.b.type() == Proxy.Type.HTTP && this.c == null) {
                        throw new RouteException(new ProtocolException("Too many tunnel connections attempted: 21"));
                    }
                    this.q = System.nanoTime();
                    return;
                }
                e(i, i2, call);
                g(c1719Ka, call);
                K k3 = this.b;
                InetSocketAddress inetSocketAddress = k3.c;
                Proxy proxy = k3.b;
                Intrinsics.checkNotNullParameter(call, "call");
                Intrinsics.checkNotNullParameter(inetSocketAddress, "inetSocketAddress");
                Intrinsics.checkNotNullParameter(proxy, "proxy");
                k = this.b;
                if (k.a.c == null) {
                }
                this.q = System.nanoTime();
                return;
            } catch (IOException e) {
                Socket socket = this.d;
                if (socket != null) {
                    okhttp3.internal.b.e(socket);
                }
                Socket socket2 = this.c;
                if (socket2 != null) {
                    okhttp3.internal.b.e(socket2);
                }
                this.d = null;
                this.c = null;
                this.h = null;
                this.i = null;
                this.e = null;
                this.f = null;
                this.g = null;
                this.o = 1;
                K k4 = this.b;
                InetSocketAddress inetSocketAddress2 = k4.c;
                Proxy proxy2 = k4.b;
                Intrinsics.checkNotNullParameter(call, "call");
                Intrinsics.checkNotNullParameter(inetSocketAddress2, "inetSocketAddress");
                Intrinsics.checkNotNullParameter(proxy2, "proxy");
                Intrinsics.checkNotNullParameter(e, "ioe");
                if (routeException == null) {
                    routeException = new RouteException(e);
                } else {
                    Intrinsics.checkNotNullParameter(e, "e");
                    C4937f.a(routeException.a, e);
                    routeException.b = e;
                }
                if (!z) {
                    throw routeException;
                }
                Intrinsics.checkNotNullParameter(e, "e");
                c1719Ka.c = true;
                if (!c1719Ka.b) {
                    throw routeException;
                }
                if (e instanceof ProtocolException) {
                    throw routeException;
                }
                if (e instanceof InterruptedIOException) {
                    throw routeException;
                }
                if ((e instanceof SSLHandshakeException) && (e.getCause() instanceof CertificateException)) {
                    throw routeException;
                }
                if (e instanceof SSLPeerUnverifiedException) {
                    throw routeException;
                }
            }
        } while (e instanceof SSLException);
        throw routeException;
    }

    public final void e(int i, int i2, InterfaceC5076e call) throws IOException {
        Socket socketCreateSocket;
        K k = this.b;
        Proxy proxy = k.b;
        C5072a c5072a = k.a;
        Proxy.Type type = proxy.type();
        int i3 = type == null ? -1 : h.a[type.ordinal()];
        if (i3 == 1 || i3 == 2) {
            socketCreateSocket = c5072a.b.createSocket();
            Intrinsics.d(socketCreateSocket);
        } else {
            socketCreateSocket = new Socket(proxy);
        }
        this.c = socketCreateSocket;
        InetSocketAddress inetSocketAddress = this.b.c;
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(inetSocketAddress, "inetSocketAddress");
        Intrinsics.checkNotNullParameter(proxy, "proxy");
        socketCreateSocket.setSoTimeout(i2);
        try {
            okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
            okhttp3.internal.platform.o.a.e(socketCreateSocket, this.b.c, i);
            try {
                this.h = AbstractC5085b.c(AbstractC5085b.k(socketCreateSocket));
                this.i = AbstractC5085b.b(AbstractC5085b.h(socketCreateSocket));
            } catch (NullPointerException e) {
                if (Intrinsics.b(e.getMessage(), "throw with null exception")) {
                    throw new IOException(e);
                }
            }
        } catch (ConnectException e2) {
            ConnectException connectException = new ConnectException("Failed to connect to " + this.b.c);
            connectException.initCause(e2);
            throw connectException;
        }
    }

    public final void f(int i, int i2, int i3, InterfaceC5076e interfaceC5076e) throws IOException {
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
        K k = this.b;
        s url = k.a.h;
        Intrinsics.checkNotNullParameter(url, "url");
        eVar.b = url;
        eVar.n("CONNECT", null);
        C5072a c5072a = k.a;
        eVar.l("Host", okhttp3.internal.b.x(c5072a.h, true));
        eVar.l("Proxy-Connection", "Keep-Alive");
        eVar.l("User-Agent", "okhttp/4.12.0");
        C request = eVar.i();
        com.android.billingclient.api.h hVar = new com.android.billingclient.api.h(3);
        Intrinsics.checkNotNullParameter(request, "request");
        B protocol = B.HTTP_1_1;
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        Intrinsics.checkNotNullParameter("Preemptive Authenticate", "message");
        I i4 = okhttp3.internal.b.c;
        Intrinsics.checkNotNullParameter("Proxy-Authenticate", "name");
        Intrinsics.checkNotNullParameter("OkHttp-Preemptive", "value");
        Intrinsics.checkNotNullParameter("Proxy-Authenticate", "name");
        Intrinsics.checkNotNullParameter("OkHttp-Preemptive", "value");
        AbstractC3343g2.b("Proxy-Authenticate");
        AbstractC3343g2.c("OkHttp-Preemptive", "Proxy-Authenticate");
        hVar.f("Proxy-Authenticate");
        hVar.b("Proxy-Authenticate", "OkHttp-Preemptive");
        H response = new H(request, protocol, "Preemptive Authenticate", com.pubmatic.sdk.video.a.VERIFICATION_EXECUTION_ERROR, null, hVar.d(), i4, null, null, null, -1L, -1L, null);
        c5072a.f.getClass();
        Intrinsics.checkNotNullParameter(response, "response");
        e(i, i2, interfaceC5076e);
        String str = "CONNECT " + okhttp3.internal.b.x(request.a, true) + " HTTP/1.1";
        A a = this.h;
        Intrinsics.d(a);
        z zVar = this.i;
        Intrinsics.d(zVar);
        C2007ea c2007ea = new C2007ea(null, this, a, zVar);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        a.a.h().g(i2, timeUnit);
        zVar.a.h().g(i3, timeUnit);
        c2007ea.m(request.c, str);
        c2007ea.a();
        G gD = c2007ea.d(false);
        Intrinsics.d(gD);
        Intrinsics.checkNotNullParameter(request, "request");
        gD.a = request;
        H response2 = gD.a();
        Intrinsics.checkNotNullParameter(response2, "response");
        long jL = okhttp3.internal.b.l(response2);
        if (jL != -1) {
            okhttp3.internal.http1.d dVarL = c2007ea.l(jL);
            okhttp3.internal.b.v(dVarL, SubsamplingScaleImageView.TILE_SIZE_AUTO);
            dVarL.close();
        }
        int i5 = response2.d;
        if (i5 == 200) {
            if (!a.b.u() || !zVar.b.u()) {
                throw new IOException("TLS tunnel buffered too many bytes!");
            }
        } else {
            if (i5 != 407) {
                throw new IOException(android.support.v4.media.session.a.f(i5, "Unexpected response code for CONNECT: "));
            }
            c5072a.f.getClass();
            Intrinsics.checkNotNullParameter(response2, "response");
            throw new IOException("Failed to authenticate with proxy");
        }
    }

    public final void g(C1719Ka c1719Ka, InterfaceC5076e call) throws Throwable {
        C5072a c5072a = this.b.a;
        SSLSocketFactory sSLSocketFactory = c5072a.c;
        B b = B.HTTP_1_1;
        if (sSLSocketFactory == null) {
            List list = c5072a.i;
            B b2 = B.H2_PRIOR_KNOWLEDGE;
            if (!list.contains(b2)) {
                this.d = this.c;
                this.f = b;
                return;
            } else {
                this.d = this.c;
                this.f = b2;
                l();
                return;
            }
        }
        Intrinsics.checkNotNullParameter(call, "call");
        C5072a c5072a2 = this.b.a;
        SSLSocketFactory sSLSocketFactory2 = c5072a2.c;
        SSLSocket sSLSocket = null;
        String strF = null;
        try {
            Intrinsics.d(sSLSocketFactory2);
            Socket socket = this.c;
            s sVar = c5072a2.h;
            Socket socketCreateSocket = sSLSocketFactory2.createSocket(socket, sVar.d, sVar.e, true);
            Intrinsics.e(socketCreateSocket, "null cannot be cast to non-null type javax.net.ssl.SSLSocket");
            SSLSocket sSLSocket2 = (SSLSocket) socketCreateSocket;
            try {
                C5082k c5082kE = c1719Ka.e(sSLSocket2);
                if (c5082kE.b) {
                    okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
                    okhttp3.internal.platform.o.a.d(sSLSocket2, c5072a2.h.d, c5072a2.i);
                }
                sSLSocket2.startHandshake();
                SSLSession sslSocketSession = sSLSocket2.getSession();
                Intrinsics.checkNotNullExpressionValue(sslSocketSession, "sslSocketSession");
                q qVarG = AbstractC3339f2.g(sslSocketSession);
                HostnameVerifier hostnameVerifier = c5072a2.d;
                Intrinsics.d(hostnameVerifier);
                if (hostnameVerifier.verify(c5072a2.h.d, sslSocketSession)) {
                    C5079h c5079h = c5072a2.e;
                    Intrinsics.d(c5079h);
                    this.e = new q(qVarG.a, qVarG.b, qVarG.c, new C0473q(c5079h, qVarG, c5072a2, 21));
                    c5079h.a(c5072a2.h.d, new t(this, 17));
                    if (c5082kE.b) {
                        okhttp3.internal.platform.o oVar2 = okhttp3.internal.platform.o.a;
                        strF = okhttp3.internal.platform.o.a.f(sSLSocket2);
                    }
                    this.d = sSLSocket2;
                    this.h = AbstractC5085b.c(AbstractC5085b.k(sSLSocket2));
                    this.i = AbstractC5085b.b(AbstractC5085b.h(sSLSocket2));
                    if (strF != null) {
                        b = AbstractC3359k2.b(strF);
                    }
                    this.f = b;
                    okhttp3.internal.platform.o oVar3 = okhttp3.internal.platform.o.a;
                    okhttp3.internal.platform.o.a.a(sSLSocket2);
                    Intrinsics.checkNotNullParameter(call, "call");
                    if (this.f == B.HTTP_2) {
                        l();
                        return;
                    }
                    return;
                }
                List listA = qVarG.a();
                if (listA.isEmpty()) {
                    throw new SSLPeerUnverifiedException("Hostname " + c5072a2.h.d + " not verified (no certificates)");
                }
                Object obj = listA.get(0);
                Intrinsics.e(obj, "null cannot be cast to non-null type java.security.cert.X509Certificate");
                X509Certificate certificate = (X509Certificate) obj;
                StringBuilder sb = new StringBuilder("\n              |Hostname ");
                sb.append(c5072a2.h.d);
                sb.append(" not verified:\n              |    certificate: ");
                C5079h c5079h2 = C5079h.c;
                sb.append(AbstractC3331d2.a(certificate));
                sb.append("\n              |    DN: ");
                sb.append(certificate.getSubjectDN().getName());
                sb.append("\n              |    subjectAltNames: ");
                Intrinsics.checkNotNullParameter(certificate, "certificate");
                sb.append(CollectionsKt.c0(okhttp3.internal.tls.c.a(certificate, 7), okhttp3.internal.tls.c.a(certificate, 2)));
                sb.append("\n              ");
                throw new SSLPeerUnverifiedException(x.d(sb.toString()));
            } catch (Throwable th) {
                th = th;
                sSLSocket = sSLSocket2;
                if (sSLSocket != null) {
                    okhttp3.internal.platform.o oVar4 = okhttp3.internal.platform.o.a;
                    okhttp3.internal.platform.o.a.a(sSLSocket);
                }
                if (sSLSocket != null) {
                    okhttp3.internal.b.e(sSLSocket);
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00b2 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(okhttp3.C5072a r9, java.util.ArrayList r10) throws java.security.NoSuchAlgorithmException {
        /*
            r8 = this;
            java.lang.String r0 = "address"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            byte[] r0 = okhttp3.internal.b.a
            java.util.ArrayList r0 = r8.p
            int r0 = r0.size()
            int r1 = r8.o
            r2 = 0
            if (r0 >= r1) goto Ld5
            boolean r0 = r8.j
            if (r0 == 0) goto L18
            goto Ld5
        L18:
            okhttp3.K r0 = r8.b
            okhttp3.a r1 = r0.a
            boolean r1 = r1.a(r9)
            if (r1 != 0) goto L24
            goto Ld5
        L24:
            okhttp3.s r1 = r9.h
            java.lang.String r3 = r1.d
            okhttp3.a r4 = r0.a
            okhttp3.s r5 = r4.h
            java.lang.String r5 = r5.d
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r3, r5)
            r5 = 1
            if (r3 == 0) goto L36
            return r5
        L36:
            okhttp3.internal.http2.n r3 = r8.g
            if (r3 != 0) goto L3c
            goto Ld5
        L3c:
            if (r10 == 0) goto Ld5
            boolean r3 = r10.isEmpty()
            if (r3 == 0) goto L46
            goto Ld5
        L46:
            java.util.Iterator r10 = r10.iterator()
        L4a:
            boolean r3 = r10.hasNext()
            if (r3 == 0) goto Ld5
            java.lang.Object r3 = r10.next()
            okhttp3.K r3 = (okhttp3.K) r3
            java.net.Proxy r6 = r3.b
            java.net.Proxy$Type r6 = r6.type()
            java.net.Proxy$Type r7 = java.net.Proxy.Type.DIRECT
            if (r6 != r7) goto L4a
            java.net.Proxy r6 = r0.b
            java.net.Proxy$Type r6 = r6.type()
            if (r6 != r7) goto L4a
            java.net.InetSocketAddress r3 = r3.c
            java.net.InetSocketAddress r6 = r0.c
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r6, r3)
            if (r3 == 0) goto L4a
            okhttp3.internal.tls.c r10 = okhttp3.internal.tls.c.a
            javax.net.ssl.HostnameVerifier r0 = r9.d
            if (r0 == r10) goto L79
            goto Ld5
        L79:
            byte[] r10 = okhttp3.internal.b.a
            okhttp3.s r10 = r4.h
            int r0 = r10.e
            int r3 = r1.e
            if (r3 == r0) goto L84
            goto Ld5
        L84:
            java.lang.String r10 = r10.d
            java.lang.String r0 = r1.d
            boolean r10 = kotlin.jvm.internal.Intrinsics.b(r0, r10)
            if (r10 == 0) goto L8f
            goto Lb2
        L8f:
            boolean r10 = r8.k
            if (r10 != 0) goto Ld5
            okhttp3.q r10 = r8.e
            if (r10 == 0) goto Ld5
            java.util.List r10 = r10.a()
            boolean r1 = r10.isEmpty()
            if (r1 != 0) goto Ld5
            java.lang.Object r10 = r10.get(r2)
            java.lang.String r1 = "null cannot be cast to non-null type java.security.cert.X509Certificate"
            kotlin.jvm.internal.Intrinsics.e(r10, r1)
            java.security.cert.X509Certificate r10 = (java.security.cert.X509Certificate) r10
            boolean r10 = okhttp3.internal.tls.c.c(r0, r10)
            if (r10 == 0) goto Ld5
        Lb2:
            okhttp3.h r9 = r9.e     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            kotlin.jvm.internal.Intrinsics.d(r9)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            okhttp3.q r10 = r8.e     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            kotlin.jvm.internal.Intrinsics.d(r10)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            java.util.List r10 = r10.a()     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            java.lang.String r1 = "hostname"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            java.lang.String r1 = "peerCertificates"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r1)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            androidx.compose.foundation.q r1 = new androidx.compose.foundation.q     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            r3 = 20
            r1.<init>(r9, r10, r0, r3)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            r9.a(r0, r1)     // Catch: javax.net.ssl.SSLPeerUnverifiedException -> Ld5
            return r5
        Ld5:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.connection.i.h(okhttp3.a, java.util.ArrayList):boolean");
    }

    public final boolean i(boolean z) throws SocketException {
        long j;
        byte[] bArr = okhttp3.internal.b.a;
        long jNanoTime = System.nanoTime();
        Socket socket = this.c;
        Intrinsics.d(socket);
        Socket socket2 = this.d;
        Intrinsics.d(socket2);
        A source = this.h;
        Intrinsics.d(source);
        if (socket.isClosed() || socket2.isClosed() || socket2.isInputShutdown() || socket2.isOutputShutdown()) {
            return false;
        }
        n nVar = this.g;
        if (nVar != null) {
            synchronized (nVar) {
                if (nVar.f) {
                    return false;
                }
                if (nVar.n < nVar.m) {
                    if (jNanoTime >= nVar.o) {
                        return false;
                    }
                }
                return true;
            }
        }
        synchronized (this) {
            j = jNanoTime - this.q;
        }
        if (j < 10000000000L || !z) {
            return true;
        }
        Intrinsics.checkNotNullParameter(socket2, "<this>");
        Intrinsics.checkNotNullParameter(source, "source");
        try {
            int soTimeout = socket2.getSoTimeout();
            try {
                socket2.setSoTimeout(1);
                return !source.u();
            } finally {
                socket2.setSoTimeout(soTimeout);
            }
        } catch (SocketTimeoutException unused) {
            return true;
        } catch (IOException unused2) {
            return false;
        }
    }

    public final okhttp3.internal.http.d j(okhttp3.A client, okhttp3.internal.http.f chain) {
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(chain, "chain");
        Socket socket = this.d;
        Intrinsics.d(socket);
        A a = this.h;
        Intrinsics.d(a);
        z zVar = this.i;
        Intrinsics.d(zVar);
        n nVar = this.g;
        if (nVar != null) {
            return new okhttp3.internal.http2.o(client, this, chain, nVar);
        }
        int i = chain.g;
        socket.setSoTimeout(i);
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        a.a.h().g(i, timeUnit);
        zVar.a.h().g(chain.h, timeUnit);
        return new C2007ea(client, this, a, zVar);
    }

    public final synchronized void k() {
        this.j = true;
    }

    public final void l() throws SocketException {
        Socket socket = this.d;
        Intrinsics.d(socket);
        A source = this.h;
        Intrinsics.d(source);
        z sink = this.i;
        Intrinsics.d(sink);
        socket.setSoTimeout(0);
        okhttp3.internal.concurrent.d taskRunner = okhttp3.internal.concurrent.d.h;
        c0 c0Var = new c0(taskRunner);
        String peerName = this.b.a.h.d;
        Intrinsics.checkNotNullParameter(socket, "socket");
        Intrinsics.checkNotNullParameter(peerName, "peerName");
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(sink, "sink");
        Intrinsics.checkNotNullParameter(socket, "<set-?>");
        c0Var.c = socket;
        String str = okhttp3.internal.b.g + ' ' + peerName;
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        c0Var.d = str;
        Intrinsics.checkNotNullParameter(source, "<set-?>");
        c0Var.e = source;
        Intrinsics.checkNotNullParameter(sink, "<set-?>");
        c0Var.f = sink;
        Intrinsics.checkNotNullParameter(this, "listener");
        c0Var.g = this;
        n nVar = new n(c0Var);
        this.g = nVar;
        okhttp3.internal.http2.z zVar = n.z;
        this.o = (zVar.a & 16) != 0 ? zVar.b[4] : SubsamplingScaleImageView.TILE_SIZE_AUTO;
        Intrinsics.checkNotNullParameter(taskRunner, "taskRunner");
        w wVar = nVar.w;
        synchronized (wVar) {
            try {
                if (wVar.d) {
                    throw new IOException("closed");
                }
                Logger logger = w.f;
                if (logger.isLoggable(Level.FINE)) {
                    logger.fine(okhttp3.internal.b.j(">> CONNECTION " + okhttp3.internal.http2.e.a.e(), new Object[0]));
                }
                wVar.a.Z(okhttp3.internal.http2.e.a);
                wVar.a.flush();
            } finally {
            }
        }
        w wVar2 = nVar.w;
        okhttp3.internal.http2.z settings = nVar.p;
        synchronized (wVar2) {
            try {
                Intrinsics.checkNotNullParameter(settings, "settings");
                if (wVar2.d) {
                    throw new IOException("closed");
                }
                wVar2.f(0, Integer.bitCount(settings.a) * 6, 4, 0);
                int i = 0;
                while (i < 10) {
                    boolean z = true;
                    if (((1 << i) & settings.a) == 0) {
                        z = false;
                    }
                    if (z) {
                        wVar2.a.f(i != 4 ? i != 7 ? i : 4 : 3);
                        wVar2.a.d(settings.b[i]);
                    }
                    i++;
                }
                wVar2.a.flush();
            } finally {
            }
        }
        if (nVar.p.a() != 65535) {
            nVar.w.q(0, r1 - 65535);
        }
        taskRunner.e().c(new okhttp3.internal.concurrent.b(nVar.c, 0, nVar.x), 0L);
    }

    public final String toString() {
        Object obj;
        StringBuilder sb = new StringBuilder("Connection{");
        K k = this.b;
        sb.append(k.a.h.d);
        sb.append(':');
        sb.append(k.a.h.e);
        sb.append(", proxy=");
        sb.append(k.b);
        sb.append(" hostAddress=");
        sb.append(k.c);
        sb.append(" cipherSuite=");
        q qVar = this.e;
        if (qVar == null || (obj = qVar.b) == null) {
            obj = IdHelperAndroid.NO_ID_AVAILABLE;
        }
        sb.append(obj);
        sb.append(" protocol=");
        sb.append(this.f);
        sb.append('}');
        return sb.toString();
    }
}
