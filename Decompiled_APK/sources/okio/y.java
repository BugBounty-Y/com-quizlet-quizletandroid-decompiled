package okio;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements G {
    public final InterfaceC5093j a;
    public final C5091h b;
    public B c;
    public int d;
    public boolean e;
    public long f;

    public y(InterfaceC5093j upstream) {
        Intrinsics.checkNotNullParameter(upstream, "upstream");
        this.a = upstream;
        C5091h c5091hC = upstream.c();
        this.b = c5091hC;
        B b = c5091hC.a;
        this.c = b;
        this.d = b != null ? b.b : -1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0020, code lost:
    
        if (r3 == r5.b) goto L15;
     */
    @Override // okio.G
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long b0(okio.C5091h r9, long r10) {
        /*
            r8 = this;
            java.lang.String r0 = "sink"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r9, r0)
            r0 = 0
            int r2 = (r10 > r0 ? 1 : (r10 == r0 ? 0 : -1))
            if (r2 < 0) goto L6b
            boolean r3 = r8.e
            if (r3 != 0) goto L63
            okio.B r3 = r8.c
            okio.h r4 = r8.b
            if (r3 == 0) goto L2b
            okio.B r5 = r4.a
            if (r3 != r5) goto L23
            int r3 = r8.d
            kotlin.jvm.internal.Intrinsics.d(r5)
            int r5 = r5.b
            if (r3 != r5) goto L23
            goto L2b
        L23:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "Peek source is invalid because upstream source was used"
            r9.<init>(r10)
            throw r9
        L2b:
            if (r2 != 0) goto L2e
            return r0
        L2e:
            long r0 = r8.f
            r2 = 1
            long r0 = r0 + r2
            okio.j r2 = r8.a
            boolean r0 = r2.e(r0)
            if (r0 != 0) goto L3e
            r9 = -1
            return r9
        L3e:
            okio.B r0 = r8.c
            if (r0 != 0) goto L4c
            okio.B r0 = r4.a
            if (r0 == 0) goto L4c
            r8.c = r0
            int r0 = r0.b
            r8.d = r0
        L4c:
            long r0 = r4.b
            long r2 = r8.f
            long r0 = r0 - r2
            long r6 = java.lang.Math.min(r10, r0)
            okio.h r2 = r8.b
            long r4 = r8.f
            r3 = r9
            r2.l(r3, r4, r6)
            long r9 = r8.f
            long r9 = r9 + r6
            r8.f = r9
            return r6
        L63:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "closed"
            r9.<init>(r10)
            throw r9
        L6b:
            java.lang.String r9 = "byteCount < 0: "
            java.lang.String r9 = androidx.compose.animation.d0.n(r10, r9)
            java.lang.IllegalArgumentException r10 = new java.lang.IllegalArgumentException
            java.lang.String r9 = r9.toString()
            r10.<init>(r9)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.y.b0(okio.h, long):long");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.e = true;
    }

    @Override // okio.G
    public final I h() {
        return this.a.h();
    }
}
