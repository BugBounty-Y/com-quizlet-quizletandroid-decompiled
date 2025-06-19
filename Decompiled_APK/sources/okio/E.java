package okio;

import java.io.Closeable;
import java.io.Flushable;

/* loaded from: classes3.dex */
public interface E extends Closeable, Flushable, AutoCloseable {
    void L(C5091h c5091h, long j);

    @Override // java.io.Closeable, java.lang.AutoCloseable
    void close();

    void flush();

    I h();
}
