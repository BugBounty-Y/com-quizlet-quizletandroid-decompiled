package okhttp3.internal.http2;

import androidx.camera.camera2.internal.c0;
import com.quizlet.features.folders.composables.W;
import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import okio.A;

/* loaded from: classes3.dex */
public final class n implements Closeable, AutoCloseable {
    public static final z z;
    public final g a;
    public final LinkedHashMap b;
    public final String c;
    public int d;
    public int e;
    public boolean f;
    public final okhttp3.internal.concurrent.d g;
    public final okhttp3.internal.concurrent.c h;
    public final okhttp3.internal.concurrent.c i;
    public final okhttp3.internal.concurrent.c j;
    public final y k;
    public long l;
    public long m;
    public long n;
    public long o;
    public final z p;
    public z q;
    public long r;
    public long s;
    public long t;
    public long u;
    public final Socket v;
    public final w w;
    public final W x;
    public final LinkedHashSet y;

    static {
        z zVar = new z();
        zVar.c(7, 65535);
        zVar.c(5, 16384);
        z = zVar;
    }

    public n(c0 builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = (g) builder.g;
        this.b = new LinkedHashMap();
        String str = (String) builder.d;
        if (str == null) {
            Intrinsics.m("connectionName");
            throw null;
        }
        this.c = str;
        this.e = 3;
        okhttp3.internal.concurrent.d dVar = (okhttp3.internal.concurrent.d) builder.b;
        this.g = dVar;
        this.h = dVar.e();
        this.i = dVar.e();
        this.j = dVar.e();
        this.k = y.a;
        z zVar = new z();
        zVar.c(7, 16777216);
        this.p = zVar;
        this.q = z;
        this.u = r0.a();
        Socket socket = (Socket) builder.c;
        if (socket == null) {
            Intrinsics.m("socket");
            throw null;
        }
        this.v = socket;
        okio.z zVar2 = (okio.z) builder.f;
        if (zVar2 == null) {
            Intrinsics.m("sink");
            throw null;
        }
        this.w = new w(zVar2);
        A a = (A) builder.e;
        if (a == null) {
            Intrinsics.m("source");
            throw null;
        }
        this.x = new W(this, new r(a));
        this.y = new LinkedHashSet();
    }

    public final void a(a connectionCode, a streamCode, IOException iOException) throws IOException {
        int i;
        Object[] array;
        Intrinsics.checkNotNullParameter(connectionCode, "connectionCode");
        Intrinsics.checkNotNullParameter(streamCode, "streamCode");
        byte[] bArr = okhttp3.internal.b.a;
        try {
            j(connectionCode);
        } catch (IOException unused) {
        }
        synchronized (this) {
            try {
                if (this.b.isEmpty()) {
                    array = null;
                } else {
                    array = this.b.values().toArray(new v[0]);
                    this.b.clear();
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        v[] vVarArr = (v[]) array;
        if (vVarArr != null) {
            for (v vVar : vVarArr) {
                try {
                    vVar.c(streamCode, iOException);
                } catch (IOException unused2) {
                }
            }
        }
        try {
            this.w.close();
        } catch (IOException unused3) {
        }
        try {
            this.v.close();
        } catch (IOException unused4) {
        }
        this.h.e();
        this.i.e();
        this.j.e();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        a(a.NO_ERROR, a.CANCEL, null);
    }

    public final void d(IOException iOException) throws IOException {
        a aVar = a.PROTOCOL_ERROR;
        a(aVar, aVar, iOException);
    }

    public final synchronized v f(int i) {
        return (v) this.b.get(Integer.valueOf(i));
    }

    public final void flush() {
        this.w.flush();
    }

    public final synchronized v i(int i) {
        v vVar;
        vVar = (v) this.b.remove(Integer.valueOf(i));
        notifyAll();
        return vVar;
    }

    public final void j(a statusCode) {
        Intrinsics.checkNotNullParameter(statusCode, "statusCode");
        synchronized (this.w) {
            synchronized (this) {
                if (this.f) {
                    return;
                }
                this.f = true;
                int i = this.d;
                Unit unit = Unit.a;
                this.w.i(i, statusCode, okhttp3.internal.b.a);
            }
        }
    }

    public final synchronized void l(long j) {
        long j2 = this.r + j;
        this.r = j2;
        long j3 = j2 - this.s;
        if (j3 >= this.p.a() / 2) {
            r(0, j3);
            this.s += j3;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0035, code lost:
    
        r2 = java.lang.Math.min((int) java.lang.Math.min(r12, r6 - r4), r8.w.c);
        r6 = r2;
        r8.t += r6;
        r4 = kotlin.Unit.a;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p(int r9, boolean r10, okio.C5091h r11, long r12) {
        /*
            r8 = this;
            r0 = 0
            int r2 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            r3 = 0
            if (r2 != 0) goto Ld
            okhttp3.internal.http2.w r12 = r8.w
            r12.d(r10, r9, r11, r3)
            return
        Ld:
            int r2 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            if (r2 <= 0) goto L6a
            monitor-enter(r8)
        L12:
            long r4 = r8.t     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            long r6 = r8.u     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            int r2 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r2 < 0) goto L34
            java.util.LinkedHashMap r2 = r8.b     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            java.lang.Integer r4 = java.lang.Integer.valueOf(r9)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            boolean r2 = r2.containsKey(r4)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            if (r2 == 0) goto L2c
            r8.wait()     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            goto L12
        L2a:
            r9 = move-exception
            goto L68
        L2c:
            java.io.IOException r9 = new java.io.IOException     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            java.lang.String r10 = "stream closed"
            r9.<init>(r10)     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
            throw r9     // Catch: java.lang.Throwable -> L2a java.lang.InterruptedException -> L5b
        L34:
            long r6 = r6 - r4
            long r4 = java.lang.Math.min(r12, r6)     // Catch: java.lang.Throwable -> L2a
            int r2 = (int) r4     // Catch: java.lang.Throwable -> L2a
            okhttp3.internal.http2.w r4 = r8.w     // Catch: java.lang.Throwable -> L2a
            int r4 = r4.c     // Catch: java.lang.Throwable -> L2a
            int r2 = java.lang.Math.min(r2, r4)     // Catch: java.lang.Throwable -> L2a
            long r4 = r8.t     // Catch: java.lang.Throwable -> L2a
            long r6 = (long) r2     // Catch: java.lang.Throwable -> L2a
            long r4 = r4 + r6
            r8.t = r4     // Catch: java.lang.Throwable -> L2a
            kotlin.Unit r4 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L2a
            monitor-exit(r8)
            long r12 = r12 - r6
            okhttp3.internal.http2.w r4 = r8.w
            if (r10 == 0) goto L56
            int r5 = (r12 > r0 ? 1 : (r12 == r0 ? 0 : -1))
            if (r5 != 0) goto L56
            r5 = 1
            goto L57
        L56:
            r5 = r3
        L57:
            r4.d(r5, r9, r11, r2)
            goto Ld
        L5b:
            java.lang.Thread r9 = java.lang.Thread.currentThread()     // Catch: java.lang.Throwable -> L2a
            r9.interrupt()     // Catch: java.lang.Throwable -> L2a
            java.io.InterruptedIOException r9 = new java.io.InterruptedIOException     // Catch: java.lang.Throwable -> L2a
            r9.<init>()     // Catch: java.lang.Throwable -> L2a
            throw r9     // Catch: java.lang.Throwable -> L2a
        L68:
            monitor-exit(r8)
            throw r9
        L6a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.n.p(int, boolean, okio.h, long):void");
    }

    public final void q(int i, a errorCode) {
        Intrinsics.checkNotNullParameter(errorCode, "errorCode");
        this.h.c(new l(this.c + '[' + i + "] writeSynReset", this, i, errorCode, 1), 0L);
    }

    public final void r(int i, long j) {
        this.h.c(new m(this.c + '[' + i + "] windowUpdate", this, i, j), 0L);
    }
}
