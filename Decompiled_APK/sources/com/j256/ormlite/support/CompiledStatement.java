package com.j256.ormlite.support;

import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.field.SqlType;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public interface CompiledStatement extends AutoCloseable {
    void cancel() throws SQLException;

    void closeQuietly();

    int getColumnCount() throws SQLException;

    String getColumnName(int i) throws SQLException;

    String getStatement();

    int runExecute() throws SQLException;

    DatabaseResults runQuery(ObjectCache objectCache) throws SQLException;

    int runUpdate() throws SQLException;

    void setMaxRows(int i) throws SQLException;

    void setObject(int i, Object obj, SqlType sqlType) throws SQLException;

    void setQueryTimeout(long j) throws SQLException;
}
