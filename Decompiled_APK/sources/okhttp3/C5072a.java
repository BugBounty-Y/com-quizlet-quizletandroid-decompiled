package okhttp3;

import androidx.compose.animation.d0;
import androidx.recyclerview.widget.C1372j;
import androidx.transition.C1405h;
import java.net.ProxySelector;
import java.util.List;
import java.util.Objects;
import javax.net.SocketFactory;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okhttp3.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5072a {
    public final o a;
    public final SocketFactory b;
    public final SSLSocketFactory c;
    public final HostnameVerifier d;
    public final C5079h e;
    public final o f;
    public final ProxySelector g;
    public final s h;
    public final List i;
    public final List j;

    public C5072a(String host, int i, o dns, SocketFactory socketFactory, SSLSocketFactory sSLSocketFactory, HostnameVerifier hostnameVerifier, C5079h c5079h, o proxyAuthenticator, List protocols, List connectionSpecs, ProxySelector proxySelector) {
        Intrinsics.checkNotNullParameter(host, "uriHost");
        Intrinsics.checkNotNullParameter(dns, "dns");
        Intrinsics.checkNotNullParameter(socketFactory, "socketFactory");
        Intrinsics.checkNotNullParameter(proxyAuthenticator, "proxyAuthenticator");
        Intrinsics.checkNotNullParameter(protocols, "protocols");
        Intrinsics.checkNotNullParameter(connectionSpecs, "connectionSpecs");
        Intrinsics.checkNotNullParameter(proxySelector, "proxySelector");
        this.a = dns;
        this.b = socketFactory;
        this.c = sSLSocketFactory;
        this.d = hostnameVerifier;
        this.e = c5079h;
        this.f = proxyAuthenticator;
        this.g = proxySelector;
        C1372j c1372j = new C1372j();
        String scheme = sSLSocketFactory != null ? "https" : "http";
        Intrinsics.checkNotNullParameter(scheme, "scheme");
        if (scheme.equalsIgnoreCase("http")) {
            c1372j.e = "http";
        } else {
            if (!scheme.equalsIgnoreCase("https")) {
                throw new IllegalArgumentException("unexpected scheme: ".concat(scheme));
            }
            c1372j.e = "https";
        }
        Intrinsics.checkNotNullParameter(host, "host");
        String strD = C1405h.d(o.f(0, 0, host, 7));
        if (strD == null) {
            throw new IllegalArgumentException("unexpected host: ".concat(host));
        }
        c1372j.h = strD;
        if (1 > i || i >= 65536) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "unexpected port: ").toString());
        }
        c1372j.b = i;
        this.h = c1372j.d();
        this.i = okhttp3.internal.b.y(protocols);
        this.j = okhttp3.internal.b.y(connectionSpecs);
    }

    public final boolean a(C5072a that) {
        Intrinsics.checkNotNullParameter(that, "that");
        return Intrinsics.b(this.a, that.a) && Intrinsics.b(this.f, that.f) && Intrinsics.b(this.i, that.i) && Intrinsics.b(this.j, that.j) && Intrinsics.b(this.g, that.g) && Intrinsics.b(this.c, that.c) && Intrinsics.b(this.d, that.d) && Intrinsics.b(this.e, that.e) && this.h.e == that.h.e;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C5072a)) {
            return false;
        }
        C5072a c5072a = (C5072a) obj;
        return Intrinsics.b(this.h, c5072a.h) && a(c5072a);
    }

    public final int hashCode() {
        return Objects.hashCode(this.e) + ((Objects.hashCode(this.d) + ((Objects.hashCode(this.c) + ((this.g.hashCode() + d0.f(d0.f((this.f.hashCode() + ((this.a.hashCode() + d0.e(527, 31, this.h.i)) * 31)) * 31, 31, this.i), 31, this.j)) * 961)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Address{");
        s sVar = this.h;
        sb.append(sVar.d);
        sb.append(':');
        sb.append(sVar.e);
        sb.append(", ");
        sb.append("proxySelector=" + this.g);
        sb.append('}');
        return sb.toString();
    }
}
