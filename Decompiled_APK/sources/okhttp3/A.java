package okhttp3;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import java.net.ProxySelector;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements Cloneable, InterfaceC5075d {
    public static final List A = okhttp3.internal.b.m(B.HTTP_2, B.HTTP_1_1);
    public static final List B = okhttp3.internal.b.m(C5082k.e, C5082k.f);
    public final com.quizlet.data.repository.explanations.exercise.b a;
    public final com.quizlet.local.ormlite.models.term.b b;
    public final List c;
    public final List d;
    public final com.quizlet.quizletandroid.ui.setcreation.imageupload.a e;
    public final boolean f;
    public final o g;
    public final boolean h;
    public final boolean i;
    public final n j;
    public final o k;
    public final ProxySelector l;
    public final o m;
    public final SocketFactory n;
    public final SSLSocketFactory o;
    public final X509TrustManager p;
    public final List q;
    public final List r;
    public final okhttp3.internal.tls.c s;
    public final C5079h t;
    public final AbstractC3375o2 u;
    public final int v;
    public final int w;
    public final int x;
    public final long y;
    public final com.quizlet.quizletandroid.ui.setcreation.managers.n z;

    public A(z builder) throws NoSuchAlgorithmException, KeyStoreException {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = builder.a;
        this.b = builder.b;
        this.c = okhttp3.internal.b.y(builder.c);
        this.d = okhttp3.internal.b.y(builder.d);
        this.e = builder.e;
        this.f = builder.f;
        this.g = builder.g;
        this.h = builder.h;
        this.i = builder.i;
        this.j = builder.j;
        this.k = builder.k;
        ProxySelector proxySelector = builder.l;
        proxySelector = proxySelector == null ? ProxySelector.getDefault() : proxySelector;
        this.l = proxySelector == null ? okhttp3.internal.proxy.a.a : proxySelector;
        this.m = builder.m;
        this.n = builder.n;
        List list = builder.q;
        this.q = list;
        this.r = builder.r;
        this.s = builder.s;
        this.v = builder.v;
        this.w = builder.w;
        this.x = builder.x;
        this.y = builder.y;
        com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = builder.z;
        this.z = nVar == null ? new com.quizlet.quizletandroid.ui.setcreation.managers.n(12) : nVar;
        if (list == null || !list.isEmpty()) {
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                if (((C5082k) it2.next()).a) {
                    SSLSocketFactory sSLSocketFactory = builder.o;
                    if (sSLSocketFactory != null) {
                        this.o = sSLSocketFactory;
                        AbstractC3375o2 certificateChainCleaner = builder.u;
                        Intrinsics.d(certificateChainCleaner);
                        this.u = certificateChainCleaner;
                        X509TrustManager x509TrustManager = builder.p;
                        Intrinsics.d(x509TrustManager);
                        this.p = x509TrustManager;
                        C5079h c5079h = builder.t;
                        c5079h.getClass();
                        Intrinsics.checkNotNullParameter(certificateChainCleaner, "certificateChainCleaner");
                        this.t = Intrinsics.b(c5079h.b, certificateChainCleaner) ? c5079h : new C5079h(c5079h.a, certificateChainCleaner);
                    } else {
                        okhttp3.internal.platform.o oVar = okhttp3.internal.platform.o.a;
                        X509TrustManager trustManager = okhttp3.internal.platform.o.a.m();
                        this.p = trustManager;
                        this.o = okhttp3.internal.platform.o.a.l(trustManager);
                        Intrinsics.checkNotNullParameter(trustManager, "trustManager");
                        AbstractC3375o2 certificateChainCleaner2 = okhttp3.internal.platform.o.a.b(trustManager);
                        this.u = certificateChainCleaner2;
                        C5079h c5079h2 = builder.t;
                        c5079h2.getClass();
                        Intrinsics.checkNotNullParameter(certificateChainCleaner2, "certificateChainCleaner");
                        this.t = Intrinsics.b(c5079h2.b, certificateChainCleaner2) ? c5079h2 : new C5079h(c5079h2.a, certificateChainCleaner2);
                    }
                }
            }
            this.o = null;
            this.u = null;
            this.p = null;
            this.t = C5079h.c;
        } else {
            this.o = null;
            this.u = null;
            this.p = null;
            this.t = C5079h.c;
        }
        List list2 = this.c;
        Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        if (list2.contains(null)) {
            throw new IllegalStateException(("Null interceptor: " + list2).toString());
        }
        List list3 = this.d;
        Intrinsics.e(list3, "null cannot be cast to non-null type kotlin.collections.List<okhttp3.Interceptor?>");
        if (list3.contains(null)) {
            throw new IllegalStateException(("Null network interceptor: " + list3).toString());
        }
        X509TrustManager x509TrustManager2 = this.p;
        AbstractC3375o2 abstractC3375o2 = this.u;
        SSLSocketFactory sSLSocketFactory2 = this.o;
        List list4 = this.q;
        if (list4 == null || !list4.isEmpty()) {
            Iterator it3 = list4.iterator();
            while (it3.hasNext()) {
                if (((C5082k) it3.next()).a) {
                    if (sSLSocketFactory2 == null) {
                        throw new IllegalStateException("sslSocketFactory == null");
                    }
                    if (abstractC3375o2 == null) {
                        throw new IllegalStateException("certificateChainCleaner == null");
                    }
                    if (x509TrustManager2 == null) {
                        throw new IllegalStateException("x509TrustManager == null");
                    }
                    return;
                }
            }
        }
        if (sSLSocketFactory2 != null) {
            throw new IllegalStateException("Check failed.");
        }
        if (abstractC3375o2 != null) {
            throw new IllegalStateException("Check failed.");
        }
        if (x509TrustManager2 != null) {
            throw new IllegalStateException("Check failed.");
        }
        if (!Intrinsics.b(this.t, C5079h.c)) {
            throw new IllegalStateException("Check failed.");
        }
    }

    public final z b() {
        Intrinsics.checkNotNullParameter(this, "okHttpClient");
        z zVar = new z();
        zVar.a = this.a;
        zVar.b = this.b;
        kotlin.collections.G.u(zVar.c, this.c);
        kotlin.collections.G.u(zVar.d, this.d);
        zVar.e = this.e;
        zVar.f = this.f;
        zVar.g = this.g;
        zVar.h = this.h;
        zVar.i = this.i;
        zVar.j = this.j;
        zVar.k = this.k;
        zVar.l = this.l;
        zVar.m = this.m;
        zVar.n = this.n;
        zVar.o = this.o;
        zVar.p = this.p;
        zVar.q = this.q;
        zVar.r = this.r;
        zVar.s = this.s;
        zVar.t = this.t;
        zVar.u = this.u;
        zVar.v = this.v;
        zVar.w = this.w;
        zVar.x = this.x;
        zVar.y = this.y;
        zVar.z = this.z;
        return zVar;
    }

    public final okhttp3.internal.connection.g c(C request) {
        Intrinsics.checkNotNullParameter(request, "request");
        return new okhttp3.internal.connection.g(this, request, false);
    }

    public final Object clone() {
        return super.clone();
    }

    public A() {
        this(new z());
    }
}
