package androidx.sqlite.db;

import java.io.Closeable;

/* loaded from: classes.dex */
public interface e extends Closeable, AutoCloseable {
    androidx.sqlite.db.framework.b I();

    void setWriteAheadLoggingEnabled(boolean z);
}
