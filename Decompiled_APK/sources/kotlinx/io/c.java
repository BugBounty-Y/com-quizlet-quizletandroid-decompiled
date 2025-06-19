package kotlinx.io;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final i a;
    public final a b;
    public g c;
    public int d;
    public boolean e;
    public long f;

    public c(i upstream) {
        Intrinsics.checkNotNullParameter(upstream, "upstream");
        this.a = upstream;
        a aVarC = upstream.c();
        this.b = aVarC;
        g gVar = aVarC.a;
        this.c = gVar;
        this.d = gVar != null ? gVar.b : -1;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0020, code lost:
    
        if (r3 == r5.b) goto L15;
     */
    @Override // kotlinx.io.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long A(kotlinx.io.a r12, long r13) {
        /*
            Method dump skipped, instructions count: 218
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.io.c.A(kotlinx.io.a, long):long");
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
        this.e = true;
    }
}
