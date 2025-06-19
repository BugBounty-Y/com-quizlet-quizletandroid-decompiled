package okhttp3.internal.http2;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayDeque;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v {
    public final int a;
    public final n b;
    public long c;
    public long d;
    public long e;
    public long f;
    public final ArrayDeque g;
    public boolean h;
    public final t i;
    public final s j;
    public final u k;
    public final u l;
    public a m;
    public IOException n;

    public v(int i, n connection, boolean z, boolean z2, okhttp3.r rVar) {
        Intrinsics.checkNotNullParameter(connection, "connection");
        this.a = i;
        this.b = connection;
        this.f = connection.q.a();
        ArrayDeque arrayDeque = new ArrayDeque();
        this.g = arrayDeque;
        this.i = new t(this, connection.p.a(), z2);
        this.j = new s(this, z);
        this.k = new u(this);
        this.l = new u(this);
        if (rVar == null) {
            if (!g()) {
                throw new IllegalStateException("remotely-initiated streams should have headers");
            }
        } else {
            if (g()) {
                throw new IllegalStateException("locally-initiated streams shouldn't have headers yet");
            }
            arrayDeque.add(rVar);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            r3 = this;
            byte[] r0 = okhttp3.internal.b.a
            monitor-enter(r3)
            okhttp3.internal.http2.t r0 = r3.i     // Catch: java.lang.Throwable -> L19
            boolean r1 = r0.b     // Catch: java.lang.Throwable -> L19
            if (r1 != 0) goto L1b
            boolean r0 = r0.e     // Catch: java.lang.Throwable -> L19
            if (r0 == 0) goto L1b
            okhttp3.internal.http2.s r0 = r3.j     // Catch: java.lang.Throwable -> L19
            boolean r1 = r0.a     // Catch: java.lang.Throwable -> L19
            if (r1 != 0) goto L17
            boolean r0 = r0.c     // Catch: java.lang.Throwable -> L19
            if (r0 == 0) goto L1b
        L17:
            r0 = 1
            goto L1c
        L19:
            r0 = move-exception
            goto L36
        L1b:
            r0 = 0
        L1c:
            boolean r1 = r3.h()     // Catch: java.lang.Throwable -> L19
            kotlin.Unit r2 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L19
            monitor-exit(r3)
            if (r0 == 0) goto L2c
            okhttp3.internal.http2.a r0 = okhttp3.internal.http2.a.CANCEL
            r1 = 0
            r3.c(r0, r1)
            return
        L2c:
            if (r1 != 0) goto L35
            okhttp3.internal.http2.n r0 = r3.b
            int r1 = r3.a
            r0.i(r1)
        L35:
            return
        L36:
            monitor-exit(r3)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.v.a():void");
    }

    public final void b() throws IOException {
        s sVar = this.j;
        if (sVar.c) {
            throw new IOException("stream closed");
        }
        if (sVar.a) {
            throw new IOException("stream finished");
        }
        if (this.m != null) {
            IOException iOException = this.n;
            if (iOException != null) {
                throw iOException;
            }
            a aVar = this.m;
            Intrinsics.d(aVar);
            throw new StreamResetException(aVar);
        }
    }

    public final void c(a statusCode, IOException iOException) {
        Intrinsics.checkNotNullParameter(statusCode, "rstStatusCode");
        if (d(statusCode, iOException)) {
            n nVar = this.b;
            nVar.getClass();
            Intrinsics.checkNotNullParameter(statusCode, "statusCode");
            nVar.w.p(this.a, statusCode);
        }
    }

    public final boolean d(a aVar, IOException iOException) {
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (this) {
            if (this.m != null) {
                return false;
            }
            this.m = aVar;
            this.n = iOException;
            notifyAll();
            if (this.i.b && this.j.a) {
                return false;
            }
            Unit unit = Unit.a;
            this.b.i(this.a);
            return true;
        }
    }

    public final void e(a errorCode) {
        Intrinsics.checkNotNullParameter(errorCode, "errorCode");
        if (d(errorCode, null)) {
            this.b.q(this.a, errorCode);
        }
    }

    public final s f() {
        synchronized (this) {
            try {
                if (!this.h && !g()) {
                    throw new IllegalStateException("reply before requesting the sink");
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        return this.j;
    }

    public final boolean g() {
        boolean z = (this.a & 1) == 1;
        this.b.getClass();
        return true == z;
    }

    public final synchronized boolean h() {
        if (this.m != null) {
            return false;
        }
        t tVar = this.i;
        if (tVar.b || tVar.e) {
            s sVar = this.j;
            if (sVar.a || sVar.c) {
                if (this.h) {
                    return false;
                }
            }
        }
        return true;
    }

    public final void i(okhttp3.r headers, boolean z) {
        boolean zH;
        Intrinsics.checkNotNullParameter(headers, "headers");
        byte[] bArr = okhttp3.internal.b.a;
        synchronized (this) {
            try {
                if (this.h && z) {
                    this.i.getClass();
                } else {
                    this.h = true;
                    this.g.add(headers);
                }
                if (z) {
                    this.i.b = true;
                }
                zH = h();
                notifyAll();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (zH) {
            return;
        }
        this.b.i(this.a);
    }

    public final synchronized void j(a errorCode) {
        Intrinsics.checkNotNullParameter(errorCode, "errorCode");
        if (this.m == null) {
            this.m = errorCode;
            notifyAll();
        }
    }

    public final void k() throws InterruptedException, InterruptedIOException {
        try {
            wait();
        } catch (InterruptedException unused) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException();
        }
    }
}
