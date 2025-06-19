package com.quizlet.db.data.database;

import android.content.Context;
import android.database.sqlite.SQLiteConstraintException;
import android.database.sqlite.SQLiteDatabase;
import com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.Where;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.orm.Relationship;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.locks.ReentrantLock;
import timber.log.c;

/* loaded from: classes2.dex */
public class DatabaseHelper extends OrmLiteSqliteOpenHelper implements DbSizeHelper {
    private static final String DATABASE_NAME = "quizletAndroid.db";
    public static final /* synthetic */ int a = 0;
    private static ReentrantLock writeLock = new ReentrantLock();
    private Long userId;

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, 114);
    }

    public static /* synthetic */ void d(DatabaseHelper databaseHelper) throws SQLException {
        databaseHelper.getClass();
        Iterator<ModelType<? extends DBModel>> it2 = Models.ALL_MODEL_TYPES.iterator();
        while (it2.hasNext()) {
            TableUtils.clearTable(databaseHelper.connectionSource, it2.next().getModelClass());
        }
    }

    @Override // com.quizlet.db.data.database.DbSizeHelper
    public final long a(Context context) {
        return context.getDatabasePath(DATABASE_NAME).length();
    }

    public final void f(Callable callable) {
        try {
            writeLock.lock();
            TransactionManager.callInTransaction(this.connectionSource, callable);
        } catch (SQLException e) {
            c.a(e);
        } finally {
            writeLock.unlock();
        }
    }

    public final Dao i(ModelType modelType) {
        return getDao(modelType.getModelClass());
    }

    public final Dao j(ModelType modelType) throws SQLException {
        Class modelClass = modelType.getModelClass();
        Dao dao = getDao(modelClass);
        if (dao == null) {
            c.a.d("Dao was null for: %s", modelClass);
        }
        return dao;
    }

    public final void l(List list, List list2, boolean z) throws SQLException {
        if (list2.size() == 0) {
            return;
        }
        Relationship relationship = (Relationship) list2.get(0);
        Map mapP = p(ModelIdentityCollection.identitiesForRelatedModels(list, relationship), z);
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            DBModel dBModel = (DBModel) it2.next();
            ModelIdentity toModelIdentity = relationship.getToModelIdentity(dBModel);
            if (toModelIdentity != null) {
                relationship.setModel(dBModel, (DBModel) mapP.get(toModelIdentity));
            }
        }
        l(new ArrayList(mapP.values()), list2.subList(1, list2.size()), z);
    }

    @Override // com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper
    public final void onCreate(SQLiteDatabase sQLiteDatabase, ConnectionSource connectionSource) {
        try {
            c.a.g("DatabaseHelper onCreate", new Object[0]);
            Iterator<ModelType<? extends DBModel>> it2 = Models.ALL_MODEL_TYPES.iterator();
            while (it2.hasNext()) {
                TableUtils.createTable(connectionSource, it2.next().getModelClass());
            }
        } catch (SQLException e) {
            c.a.f(e, "Can't create database", new Object[0]);
            throw new RuntimeException(e);
        }
    }

    @Override // com.j256.ormlite.android.apptools.OrmLiteSqliteOpenHelper
    public final void onUpgrade(SQLiteDatabase sQLiteDatabase, ConnectionSource connectionSource, int i, int i2) {
        new DatabaseMigrator(this, this.userId).b(sQLiteDatabase, connectionSource, i, i2);
    }

    public final Map p(ModelIdentityCollection modelIdentityCollection, boolean z) throws SQLException {
        ModelType modelType = modelIdentityCollection.getModelType();
        if (modelType == null) {
            return new HashMap();
        }
        Where where = j(modelType).queryBuilder().where();
        if (!z) {
            where = where.eq("isDeleted", Boolean.FALSE).and();
        }
        modelIdentityCollection.whereIn(where);
        return ModelIdentityProvider.identityMap(where.query());
    }

    public final void q(List list) throws SQLException {
        if (list == null) {
            return;
        }
        for (int i = 0; i < list.size(); i++) {
            DBModel dBModel = (DBModel) list.get(i);
            if (dBModel.getLocalId() == 0) {
                throw new IllegalArgumentException("LocalId must be assigned before save");
            }
            Dao daoJ = j(dBModel.getModelType());
            try {
                if (daoJ.update((Dao) dBModel) == 0) {
                    daoJ.create((Dao) dBModel);
                }
            } catch (SQLException e) {
                if (!(e.getCause().getCause() instanceof SQLiteConstraintException)) {
                    throw e;
                }
                ModelIdentity identity = dBModel.getIdentity();
                c.a.o("Violated identity constraint on %s with identity %s", dBModel.getClass(), identity);
                List listQuery = identity.whereEq(daoJ.queryBuilder().where()).query();
                if (listQuery.size() != 1 || ((DBModel) listQuery.get(0)).getLocalId() == 0) {
                    ModelIdentity identity2 = dBModel.getIdentity();
                    DeleteBuilder deleteBuilder = j(dBModel.getModelType()).deleteBuilder();
                    identity2.whereEq(deleteBuilder.where());
                    int iDelete = deleteBuilder.delete();
                    if (iDelete != 1) {
                        c.a(new RuntimeException(android.support.v4.media.session.a.f(iDelete, "Deleted unexpected number of records when resolving identity conflict: ")));
                    }
                } else {
                    dBModel.setLocalId(((DBModel) listQuery.get(0)).getLocalId());
                }
                daoJ.createOrUpdate(dBModel);
            }
        }
    }

    public final Where r(ModelType modelType, boolean z) throws SQLException {
        Dao dao = getDao(modelType.getModelClass());
        if (dao != null) {
            Where<T, ID> where = dao.queryBuilder().where();
            return !z ? where.eq("isDeleted", Boolean.FALSE).and() : where;
        }
        c.a.d("Dao was null for: %s", modelType);
        throw new NullPointerException("dao == null");
    }

    public void setUserId(Long l) {
        this.userId = l;
    }
}
