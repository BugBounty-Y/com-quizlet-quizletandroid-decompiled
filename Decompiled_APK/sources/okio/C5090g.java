package okio;

import java.io.Closeable;

/* renamed from: okio.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5090g implements Closeable, AutoCloseable {
    public C5091h a;

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        if (this.a == null) {
            throw new IllegalStateException("not attached to a buffer");
        }
        this.a = null;
    }
}
