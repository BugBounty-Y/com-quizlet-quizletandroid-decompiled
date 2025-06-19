package okio;

import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p extends I {
    public I e;

    public p(I delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.e = delegate;
    }

    @Override // okio.I
    public final I a() {
        return this.e.a();
    }

    @Override // okio.I
    public final I b() {
        return this.e.b();
    }

    @Override // okio.I
    public final long c() {
        return this.e.c();
    }

    @Override // okio.I
    public final I d(long j) {
        return this.e.d(j);
    }

    @Override // okio.I
    public final boolean e() {
        return this.e.e();
    }

    @Override // okio.I
    public final void f() throws InterruptedIOException {
        this.e.f();
    }

    @Override // okio.I
    public final I g(long j, TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        return this.e.g(j, unit);
    }
}
