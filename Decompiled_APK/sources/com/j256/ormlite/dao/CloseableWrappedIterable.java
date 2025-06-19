package com.j256.ormlite.dao;

/* loaded from: classes2.dex */
public interface CloseableWrappedIterable<T> extends CloseableIterable<T>, AutoCloseable {
    @Override // java.lang.AutoCloseable
    void close() throws Exception;

    @Override // com.j256.ormlite.dao.CloseableIterable
    /* synthetic */ CloseableIterator closeableIterator();
}
