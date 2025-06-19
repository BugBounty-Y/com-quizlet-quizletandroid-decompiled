package okhttp3.internal.http2;

import kotlin.Unit;
import okio.C5091h;
import okio.G;
import okio.I;

/* loaded from: classes3.dex */
public final class t implements G {
    public final long a;
    public boolean b;
    public final C5091h c = new C5091h();
    public final C5091h d = new C5091h();
    public boolean e;
    public final /* synthetic */ v f;

    public t(v vVar, long j, boolean z) {
        this.f = vVar;
        this.a = j;
        this.b = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x0089 A[LOOP:0: B:4:0x000e->B:45:0x0089, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x008c A[SYNTHETIC] */
    @Override // okio.G
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long b0(okio.C5091h r15, long r16) throws java.lang.Throwable {
        /*
            r14 = this;
            r0 = r15
            r1 = r16
            java.lang.String r3 = "sink"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r15, r3)
            r3 = 0
            int r5 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r5 < 0) goto Laa
        Le:
            okhttp3.internal.http2.v r5 = r14.f
            monitor-enter(r5)
            okhttp3.internal.http2.u r6 = r5.k     // Catch: java.lang.Throwable -> L95
            r6.h()     // Catch: java.lang.Throwable -> L95
            monitor-enter(r5)     // Catch: java.lang.Throwable -> L31
            okhttp3.internal.http2.a r6 = r5.m     // Catch: java.lang.Throwable -> L9f
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L31
            if (r6 == 0) goto L37
            boolean r6 = r14.b     // Catch: java.lang.Throwable -> L31
            if (r6 != 0) goto L37
            java.io.IOException r6 = r5.n     // Catch: java.lang.Throwable -> L31
            if (r6 != 0) goto L38
            okhttp3.internal.http2.StreamResetException r6 = new okhttp3.internal.http2.StreamResetException     // Catch: java.lang.Throwable -> L31
            monitor-enter(r5)     // Catch: java.lang.Throwable -> L31
            okhttp3.internal.http2.a r7 = r5.m     // Catch: java.lang.Throwable -> L34
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L31
            kotlin.jvm.internal.Intrinsics.d(r7)     // Catch: java.lang.Throwable -> L31
            r6.<init>(r7)     // Catch: java.lang.Throwable -> L31
            goto L38
        L31:
            r0 = move-exception
            goto La2
        L34:
            r0 = move-exception
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L34
            throw r0     // Catch: java.lang.Throwable -> L31
        L37:
            r6 = 0
        L38:
            boolean r7 = r14.e     // Catch: java.lang.Throwable -> L31
            if (r7 != 0) goto L97
            okio.h r7 = r14.d     // Catch: java.lang.Throwable -> L31
            long r8 = r7.b     // Catch: java.lang.Throwable -> L31
            int r10 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            r11 = -1
            r13 = 0
            if (r10 <= 0) goto L74
            long r8 = java.lang.Math.min(r1, r8)     // Catch: java.lang.Throwable -> L31
            long r7 = r7.b0(r15, r8)     // Catch: java.lang.Throwable -> L31
            long r9 = r5.c     // Catch: java.lang.Throwable -> L31
            long r9 = r9 + r7
            r5.c = r9     // Catch: java.lang.Throwable -> L31
            long r3 = r5.d     // Catch: java.lang.Throwable -> L31
            long r9 = r9 - r3
            if (r6 != 0) goto L7f
            okhttp3.internal.http2.n r3 = r5.b     // Catch: java.lang.Throwable -> L31
            okhttp3.internal.http2.z r3 = r3.p     // Catch: java.lang.Throwable -> L31
            int r3 = r3.a()     // Catch: java.lang.Throwable -> L31
            int r3 = r3 / 2
            long r3 = (long) r3     // Catch: java.lang.Throwable -> L31
            int r3 = (r9 > r3 ? 1 : (r9 == r3 ? 0 : -1))
            if (r3 < 0) goto L7f
            okhttp3.internal.http2.n r3 = r5.b     // Catch: java.lang.Throwable -> L31
            int r4 = r5.a     // Catch: java.lang.Throwable -> L31
            r3.r(r4, r9)     // Catch: java.lang.Throwable -> L31
            long r3 = r5.c     // Catch: java.lang.Throwable -> L31
            r5.d = r3     // Catch: java.lang.Throwable -> L31
            goto L7f
        L74:
            boolean r3 = r14.b     // Catch: java.lang.Throwable -> L31
            if (r3 != 0) goto L7e
            if (r6 != 0) goto L7e
            r5.k()     // Catch: java.lang.Throwable -> L31
            r13 = 1
        L7e:
            r7 = r11
        L7f:
            okhttp3.internal.http2.u r3 = r5.k     // Catch: java.lang.Throwable -> L95
            r3.k()     // Catch: java.lang.Throwable -> L95
            kotlin.Unit r3 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L95
            monitor-exit(r5)
            if (r13 == 0) goto L8c
            r3 = 0
            goto Le
        L8c:
            int r0 = (r7 > r11 ? 1 : (r7 == r11 ? 0 : -1))
            if (r0 == 0) goto L91
            return r7
        L91:
            if (r6 != 0) goto L94
            return r11
        L94:
            throw r6
        L95:
            r0 = move-exception
            goto La8
        L97:
            java.io.IOException r0 = new java.io.IOException     // Catch: java.lang.Throwable -> L31
            java.lang.String r1 = "stream closed"
            r0.<init>(r1)     // Catch: java.lang.Throwable -> L31
            throw r0     // Catch: java.lang.Throwable -> L31
        L9f:
            r0 = move-exception
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L9f
            throw r0     // Catch: java.lang.Throwable -> L31
        La2:
            okhttp3.internal.http2.u r1 = r5.k     // Catch: java.lang.Throwable -> L95
            r1.k()     // Catch: java.lang.Throwable -> L95
            throw r0     // Catch: java.lang.Throwable -> L95
        La8:
            monitor-exit(r5)
            throw r0
        Laa:
            java.lang.String r0 = "byteCount < 0: "
            java.lang.String r0 = androidx.compose.animation.d0.n(r1, r0)
            java.lang.IllegalArgumentException r1 = new java.lang.IllegalArgumentException
            java.lang.String r0 = r0.toString()
            r1.<init>(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: okhttp3.internal.http2.t.b0(okio.h, long):long");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        long j;
        v vVar = this.f;
        synchronized (vVar) {
            this.e = true;
            C5091h c5091h = this.d;
            j = c5091h.b;
            c5091h.d();
            vVar.notifyAll();
            Unit unit = Unit.a;
        }
        if (j > 0) {
            byte[] bArr = okhttp3.internal.b.a;
            this.f.b.l(j);
        }
        this.f.a();
    }

    @Override // okio.G
    public final I h() {
        return this.f.k;
    }
}
