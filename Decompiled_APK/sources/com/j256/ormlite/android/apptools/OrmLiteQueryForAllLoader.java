package com.j256.ormlite.android.apptools;

import android.content.Context;
import com.j256.ormlite.dao.Dao;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public class OrmLiteQueryForAllLoader<T, ID> extends BaseOrmLiteLoader<T, ID> {
    public OrmLiteQueryForAllLoader(Context context) {
        super(context);
    }

    public OrmLiteQueryForAllLoader(Context context, Dao<T, ID> dao) {
        super(context, dao);
    }

    @Override // android.content.AsyncTaskLoader
    public List<T> loadInBackground() {
        Dao<T, ID> dao = this.dao;
        if (dao == null) {
            throw new IllegalStateException("Dao is not initialized.");
        }
        try {
            return dao.queryForAll();
        } catch (SQLException e) {
            e.printStackTrace();
            return Collections.EMPTY_LIST;
        }
    }
}
