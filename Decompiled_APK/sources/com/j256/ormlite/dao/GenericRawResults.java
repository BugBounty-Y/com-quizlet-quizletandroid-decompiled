package com.j256.ormlite.dao;

import java.sql.SQLException;
import java.util.List;

/* loaded from: classes2.dex */
public interface GenericRawResults<T> extends CloseableWrappedIterable<T> {
    @Override // com.j256.ormlite.dao.CloseableWrappedIterable, java.lang.AutoCloseable
    void close() throws Exception;

    @Override // com.j256.ormlite.dao.CloseableWrappedIterable, com.j256.ormlite.dao.CloseableIterable
    /* synthetic */ CloseableIterator closeableIterator();

    String[] getColumnNames();

    T getFirstResult() throws SQLException;

    int getNumberColumns();

    List<T> getResults() throws SQLException;
}
