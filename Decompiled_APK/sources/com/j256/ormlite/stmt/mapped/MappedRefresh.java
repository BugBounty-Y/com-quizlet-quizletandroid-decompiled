package com.j256.ormlite.stmt.mapped;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableInfo;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class MappedRefresh<T, ID> extends MappedQueryForFieldEq<T, ID> {
    private MappedRefresh(Dao<T, ID> dao, TableInfo<T, ID> tableInfo, String str, FieldType[] fieldTypeArr, FieldType[] fieldTypeArr2) {
        super(dao, tableInfo, str, fieldTypeArr, fieldTypeArr2, "refresh");
    }

    public static <T, ID> MappedRefresh<T, ID> build(Dao<T, ID> dao, TableInfo<T, ID> tableInfo) throws SQLException {
        FieldType idField = tableInfo.getIdField();
        if (idField != null) {
            return new MappedRefresh<>(dao, tableInfo, MappedQueryForFieldEq.buildStatement(dao.getConnectionSource().getDatabaseType(), tableInfo, idField), new FieldType[]{tableInfo.getIdField()}, tableInfo.getFieldTypes());
        }
        throw new SQLException("Cannot refresh " + tableInfo.getDataClass() + " because it doesn't have an id field");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int executeRefresh(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        T t2;
        ObjectCache objectCache2;
        Object objExecute = super.execute(databaseConnection, this.idField.extractJavaFieldValue(t), null);
        int i = 0;
        if (objExecute == null) {
            return 0;
        }
        FieldType[] fieldTypeArr = this.resultsFieldTypes;
        int length = fieldTypeArr.length;
        while (i < length) {
            FieldType fieldType = fieldTypeArr[i];
            if (fieldType != this.idField) {
                t2 = t;
                objectCache2 = objectCache;
                fieldType.assignField(this.connectionSource, t2, fieldType.extractJavaFieldValue(objExecute), false, objectCache2);
            } else {
                t2 = t;
                objectCache2 = objectCache;
            }
            i++;
            t = t2;
            objectCache = objectCache2;
        }
        return 1;
    }
}
