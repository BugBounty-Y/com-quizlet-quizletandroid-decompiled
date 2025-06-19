package com.j256.ormlite.stmt.mapped;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableInfo;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class MappedDelete<T, ID> extends BaseMappedStatement<T, ID> {
    private MappedDelete(Dao<T, ID> dao, TableInfo<T, ID> tableInfo, String str, FieldType[] fieldTypeArr) {
        super(dao, tableInfo, str, fieldTypeArr);
    }

    public static <T, ID> MappedDelete<T, ID> build(Dao<T, ID> dao, TableInfo<T, ID> tableInfo) throws SQLException {
        FieldType idField = tableInfo.getIdField();
        if (idField == null) {
            throw new SQLException("Cannot delete from " + tableInfo.getDataClass() + " because it doesn't have an id field");
        }
        StringBuilder sb = new StringBuilder(64);
        DatabaseType databaseType = dao.getConnectionSource().getDatabaseType();
        BaseMappedStatement.appendTableName(databaseType, sb, "DELETE FROM ", (TableInfo<?, ?>) tableInfo);
        BaseMappedStatement.appendWhereFieldEq(databaseType, idField, sb, null);
        return new MappedDelete<>(dao, tableInfo, sb.toString(), new FieldType[]{idField});
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int delete(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws SQLException {
        try {
            Object[] fieldObjects = getFieldObjects(t);
            int iDelete = databaseConnection.delete(this.statement, fieldObjects, this.argFieldTypes);
            BaseMappedStatement.logger.debug("delete data with statement '{}' and {} args, changed {} rows", this.statement, Integer.valueOf(fieldObjects.length), Integer.valueOf(iDelete));
            if (fieldObjects.length > 0) {
                BaseMappedStatement.logger.trace("delete arguments: {}", (Object) fieldObjects);
            }
            if (iDelete > 0 && objectCache != 0) {
                objectCache.remove(this.clazz, this.idField.extractJavaFieldToSqlArgValue(t));
            }
            return iDelete;
        } catch (SQLException e) {
            throw new SQLException("Unable to run delete stmt on object " + t + ": " + this.statement, e);
        }
    }

    public int deleteById(DatabaseConnection databaseConnection, ID id, ObjectCache objectCache) throws SQLException {
        try {
            Object[] objArr = {convertIdToFieldObject(id)};
            int iDelete = databaseConnection.delete(this.statement, objArr, this.argFieldTypes);
            BaseMappedStatement.logger.debug("delete data with statement '{}' and {} args, changed {} rows", (Object) this.statement, (Object) 1, (Object) Integer.valueOf(iDelete));
            BaseMappedStatement.logger.trace("delete arguments: {}", (Object) objArr);
            if (iDelete <= 0 || objectCache == null) {
                return iDelete;
            }
            objectCache.remove(this.clazz, id);
            return iDelete;
        } catch (SQLException e) {
            throw new SQLException("Unable to run deleteById stmt on id " + id + ": " + this.statement, e);
        }
    }
}
