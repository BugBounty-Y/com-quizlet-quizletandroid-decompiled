package okhttp3.internal.http2;

import androidx.appcompat.widget.C0122z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3371n2;
import java.io.IOException;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okhttp3.A;
import okhttp3.B;
import okhttp3.C;
import okhttp3.H;
import okio.E;
import okio.G;

/* loaded from: classes3.dex */
public final class o implements okhttp3.internal.http.d {
    public static final List g = okhttp3.internal.b.m("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade", ":method", ":path", ":scheme", ":authority");
    public static final List h = okhttp3.internal.b.m("connection", "host", "keep-alive", "proxy-connection", "te", "transfer-encoding", "encoding", "upgrade");
    public final okhttp3.internal.connection.i a;
    public final okhttp3.internal.http.f b;
    public final n c;
    public volatile v d;
    public final B e;
    public volatile boolean f;

    public o(A client, okhttp3.internal.connection.i connection, okhttp3.internal.http.f chain, n http2Connection) {
        Intrinsics.checkNotNullParameter(client, "client");
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(chain, "chain");
        Intrinsics.checkNotNullParameter(http2Connection, "http2Connection");
        this.a = connection;
        this.b = chain;
        this.c = http2Connection;
        List list = client.r;
        B b = B.H2_PRIOR_KNOWLEDGE;
        this.e = list.contains(b) ? b : B.HTTP_2;
    }

    @Override // okhttp3.internal.http.d
    public final void a() {
        v vVar = this.d;
        Intrinsics.d(vVar);
        vVar.f().close();
    }

    @Override // okhttp3.internal.http.d
    public final void b(C request) throws IOException {
        int i;
        v vVar;
        boolean z = true;
        Intrinsics.checkNotNullParameter(request, "request");
        if (this.d != null) {
            return;
        }
        boolean z2 = request.d != null;
        Intrinsics.checkNotNullParameter(request, "request");
        okhttp3.r rVar = request.c;
        ArrayList requestHeaders = new ArrayList(rVar.size() + 4);
        requestHeaders.add(new b(b.f, request.b));
        okio.k kVar = b.g;
        okhttp3.s url = request.a;
        Intrinsics.checkNotNullParameter(url, "url");
        String strB = url.b();
        String strD = url.d();
        if (strD != null) {
            strB = strB + '?' + strD;
        }
        requestHeaders.add(new b(kVar, strB));
        String strA = request.a("Host");
        if (strA != null) {
            requestHeaders.add(new b(b.i, strA));
        }
        requestHeaders.add(new b(b.h, url.a));
        int size = rVar.size();
        for (int i2 = 0; i2 < size; i2++) {
            String strB2 = rVar.b(i2);
            Locale locale = Locale.US;
            String strK = androidx.compose.ui.node.B.k(locale, "US", strB2, locale, "this as java.lang.String).toLowerCase(locale)");
            if (!g.contains(strK) || (Intrinsics.b(strK, "te") && Intrinsics.b(rVar.g(i2), "trailers"))) {
                requestHeaders.add(new b(strK, rVar.g(i2)));
            }
        }
        n nVar = this.c;
        nVar.getClass();
        Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
        boolean z3 = !z2;
        synchronized (nVar.w) {
            synchronized (nVar) {
                try {
                    if (nVar.e > 1073741823) {
                        nVar.j(a.REFUSED_STREAM);
                    }
                    if (nVar.f) {
                        throw new ConnectionShutdownException();
                    }
                    i = nVar.e;
                    nVar.e = i + 2;
                    vVar = new v(i, nVar, z3, false, null);
                    if (z2 && nVar.t < nVar.u && vVar.e < vVar.f) {
                        z = false;
                    }
                    if (vVar.h()) {
                        nVar.b.put(Integer.valueOf(i), vVar);
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            nVar.w.j(i, requestHeaders, z3);
        }
        if (z) {
            nVar.w.flush();
        }
        this.d = vVar;
        if (this.f) {
            v vVar2 = this.d;
            Intrinsics.d(vVar2);
            vVar2.e(a.CANCEL);
            throw new IOException("Canceled");
        }
        v vVar3 = this.d;
        Intrinsics.d(vVar3);
        u uVar = vVar3.k;
        long j = this.b.g;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        uVar.g(j, timeUnit);
        v vVar4 = this.d;
        Intrinsics.d(vVar4);
        vVar4.l.g(this.b.h, timeUnit);
    }

    @Override // okhttp3.internal.http.d
    public final G c(H response) {
        Intrinsics.checkNotNullParameter(response, "response");
        v vVar = this.d;
        Intrinsics.d(vVar);
        return vVar.i;
    }

    @Override // okhttp3.internal.http.d
    public final void cancel() {
        this.f = true;
        v vVar = this.d;
        if (vVar != null) {
            vVar.e(a.CANCEL);
        }
    }

    @Override // okhttp3.internal.http.d
    public final okhttp3.G d(boolean z) throws IOException {
        okhttp3.r headerBlock;
        v vVar = this.d;
        if (vVar == null) {
            throw new IOException("stream wasn't created");
        }
        synchronized (vVar) {
            vVar.k.h();
            while (vVar.g.isEmpty() && vVar.m == null) {
                try {
                    vVar.k();
                } catch (Throwable th) {
                    vVar.k.k();
                    throw th;
                }
            }
            vVar.k.k();
            if (vVar.g.isEmpty()) {
                IOException iOException = vVar.n;
                if (iOException != null) {
                    throw iOException;
                }
                a aVar = vVar.m;
                Intrinsics.d(aVar);
                throw new StreamResetException(aVar);
            }
            Object objRemoveFirst = vVar.g.removeFirst();
            Intrinsics.checkNotNullExpressionValue(objRemoveFirst, "headersQueue.removeFirst()");
            headerBlock = (okhttp3.r) objRemoveFirst;
        }
        B protocol = this.e;
        Intrinsics.checkNotNullParameter(headerBlock, "headerBlock");
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        ArrayList arrayList = new ArrayList(20);
        int size = headerBlock.size();
        C0122z c0122zB = null;
        for (int i = 0; i < size; i++) {
            String name = headerBlock.b(i);
            String value = headerBlock.g(i);
            if (Intrinsics.b(name, ":status")) {
                c0122zB = AbstractC3371n2.b("HTTP/1.1 " + value);
            } else if (!h.contains(name)) {
                Intrinsics.checkNotNullParameter(name, "name");
                Intrinsics.checkNotNullParameter(value, "value");
                arrayList.add(name);
                arrayList.add(StringsKt.g0(value).toString());
            }
        }
        if (c0122zB == null) {
            throw new ProtocolException("Expected ':status' header not present");
        }
        okhttp3.G g2 = new okhttp3.G();
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        g2.b = protocol;
        g2.c = c0122zB.b;
        String message = (String) c0122zB.d;
        Intrinsics.checkNotNullParameter(message, "message");
        g2.d = message;
        okhttp3.r headers = new okhttp3.r((String[]) arrayList.toArray(new String[0]));
        Intrinsics.checkNotNullParameter(headers, "headers");
        g2.f = headers.e();
        if (z && g2.c == 100) {
            return null;
        }
        return g2;
    }

    @Override // okhttp3.internal.http.d
    public final okhttp3.internal.connection.i e() {
        return this.a;
    }

    @Override // okhttp3.internal.http.d
    public final void f() {
        this.c.flush();
    }

    @Override // okhttp3.internal.http.d
    public final long g(H response) {
        Intrinsics.checkNotNullParameter(response, "response");
        if (okhttp3.internal.http.e.a(response)) {
            return okhttp3.internal.b.l(response);
        }
        return 0L;
    }

    @Override // okhttp3.internal.http.d
    public final E h(C request, long j) {
        Intrinsics.checkNotNullParameter(request, "request");
        v vVar = this.d;
        Intrinsics.d(vVar);
        return vVar.f();
    }
}
