package com.j256.ormlite.android.apptools;

import android.content.Context;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.stmt.PreparedQuery;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public class OrmLitePreparedQueryLoader<T, ID> extends BaseOrmLiteLoader<T, ID> {
    private PreparedQuery<T> preparedQuery;

    public OrmLitePreparedQueryLoader(Context context) {
        super(context);
    }

    public PreparedQuery<T> getPreparedQuery() {
        return this.preparedQuery;
    }

    public void setPreparedQuery(PreparedQuery<T> preparedQuery) {
        this.preparedQuery = preparedQuery;
    }

    public OrmLitePreparedQueryLoader(Context context, Dao<T, ID> dao, PreparedQuery<T> preparedQuery) {
        super(context, dao);
        this.preparedQuery = preparedQuery;
    }

    @Override // android.content.AsyncTaskLoader
    public List<T> loadInBackground() {
        Dao<T, ID> dao = this.dao;
        if (dao == null) {
            throw new IllegalStateException("Dao is not initialized.");
        }
        PreparedQuery<T> preparedQuery = this.preparedQuery;
        if (preparedQuery == null) {
            throw new IllegalStateException("PreparedQuery is not initialized.");
        }
        try {
            return dao.query(preparedQuery);
        } catch (SQLException e) {
            e.printStackTrace();
            return Collections.EMPTY_LIST;
        }
    }
}
