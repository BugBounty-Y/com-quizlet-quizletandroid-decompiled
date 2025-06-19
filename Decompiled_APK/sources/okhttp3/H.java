package okhttp3;

import java.io.Closeable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H implements Closeable, AutoCloseable {
    public final C a;
    public final B b;
    public final String c;
    public final int d;
    public final q e;
    public final r f;
    public final J g;
    public final H h;
    public final H i;
    public final H j;
    public final long k;
    public final long l;
    public final androidx.compose.material.ripple.r m;

    public H(C request, B protocol, String message, int i, q qVar, r headers, J j, H h, H h2, H h3, long j2, long j3, androidx.compose.material.ripple.r rVar) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(protocol, "protocol");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(headers, "headers");
        this.a = request;
        this.b = protocol;
        this.c = message;
        this.d = i;
        this.e = qVar;
        this.f = headers;
        this.g = j;
        this.h = h;
        this.i = h2;
        this.j = h3;
        this.k = j2;
        this.l = j3;
        this.m = rVar;
    }

    public static String a(String name, H h) {
        h.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        String strA = h.f.a(name);
        if (strA == null) {
            return null;
        }
        return strA;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        J j = this.g;
        if (j == null) {
            throw new IllegalStateException("response is not eligible for a body and must not be closed");
        }
        j.close();
    }

    public final boolean d() {
        int i = this.d;
        return 200 <= i && i < 300;
    }

    public final G f() {
        Intrinsics.checkNotNullParameter(this, "response");
        G g = new G();
        g.a = this.a;
        g.b = this.b;
        g.c = this.d;
        g.d = this.c;
        g.e = this.e;
        g.f = this.f.e();
        g.g = this.g;
        g.h = this.h;
        g.i = this.i;
        g.j = this.j;
        g.k = this.k;
        g.l = this.l;
        g.m = this.m;
        return g;
    }

    public final String toString() {
        return "Response{protocol=" + this.b + ", code=" + this.d + ", message=" + this.c + ", url=" + this.a.a + '}';
    }
}
