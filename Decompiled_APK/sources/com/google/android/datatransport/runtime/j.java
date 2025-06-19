package com.google.android.datatransport.runtime;

import java.io.Closeable;

/* loaded from: classes2.dex */
public final class j implements Closeable, AutoCloseable {
    public javax.inject.a a;
    public com.google.android.datatransport.runtime.backends.e b;
    public javax.inject.a c;
    public com.google.android.datatransport.runtime.backends.e d;
    public javax.inject.a e;
    public javax.inject.a f;

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        ((com.google.android.datatransport.runtime.scheduling.persistence.g) ((com.google.android.datatransport.runtime.scheduling.persistence.d) this.e.get())).close();
    }
}
