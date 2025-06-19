package okio;

import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class o implements G {
    public final G a;

    public o(G delegate) {
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.a = delegate;
    }

    @Override // okio.G
    public long b0(C5091h sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        return this.a.b0(sink, j);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.a.close();
    }

    @Override // okio.G
    public final I h() {
        return this.a.h();
    }

    public final String toString() {
        return getClass().getSimpleName() + '(' + this.a + ')';
    }
}
