package okio;

import java.io.EOFException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: okio.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5089f implements E {
    @Override // okio.E
    public final void L(C5091h source, long j) throws EOFException {
        Intrinsics.checkNotNullParameter(source, "source");
        source.skip(j);
    }

    @Override // okio.E, java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    @Override // okio.E, java.io.Flushable
    public final void flush() {
    }

    @Override // okio.E
    public final I h() {
        return I.d;
    }
}
