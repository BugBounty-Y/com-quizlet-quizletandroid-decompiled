package com.j256.ormlite.stmt.mapped;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableInfo;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class MappedUpdate<T, ID> extends BaseMappedStatement<T, ID> {
    private final FieldType versionFieldType;
    private final int versionFieldTypeIndex;

    private MappedUpdate(Dao<T, ID> dao, TableInfo<T, ID> tableInfo, String str, FieldType[] fieldTypeArr, FieldType fieldType, int i) {
        super(dao, tableInfo, str, fieldTypeArr);
        this.versionFieldType = fieldType;
        this.versionFieldTypeIndex = i;
    }

    public static <T, ID> MappedUpdate<T, ID> build(Dao<T, ID> dao, TableInfo<T, ID> tableInfo) throws SQLException {
        FieldType idField = tableInfo.getIdField();
        if (idField == null) {
            throw new SQLException("Cannot update " + tableInfo.getDataClass() + " because it doesn't have an id field");
        }
        StringBuilder sb = new StringBuilder(64);
        DatabaseType databaseType = dao.getConnectionSource().getDatabaseType();
        BaseMappedStatement.appendTableName(databaseType, sb, "UPDATE ", (TableInfo<?, ?>) tableInfo);
        FieldType fieldType = null;
        int i = -1;
        int i2 = 0;
        for (FieldType fieldType2 : tableInfo.getFieldTypes()) {
            if (isFieldUpdatable(fieldType2, idField)) {
                if (fieldType2.isVersion()) {
                    i = i2;
                    fieldType = fieldType2;
                }
                i2++;
            }
        }
        int i3 = i2 + 1;
        if (fieldType != null) {
            i3 = i2 + 2;
        }
        FieldType[] fieldTypeArr = new FieldType[i3];
        boolean z = true;
        int i4 = 0;
        for (FieldType fieldType3 : tableInfo.getFieldTypes()) {
            if (isFieldUpdatable(fieldType3, idField)) {
                if (z) {
                    sb.append("SET ");
                    z = false;
                } else {
                    sb.append(", ");
                }
                BaseMappedStatement.appendFieldColumnName(databaseType, sb, fieldType3, null);
                fieldTypeArr[i4] = fieldType3;
                sb.append("= ?");
                i4++;
            }
        }
        sb.append(' ');
        BaseMappedStatement.appendWhereFieldEq(databaseType, idField, sb, null);
        int i5 = i4 + 1;
        fieldTypeArr[i4] = idField;
        if (fieldType != null) {
            sb.append(" AND ");
            BaseMappedStatement.appendFieldColumnName(databaseType, sb, fieldType, null);
            sb.append("= ?");
            fieldTypeArr[i5] = fieldType;
        }
        return new MappedUpdate<>(dao, tableInfo, sb.toString(), fieldTypeArr, fieldType, i);
    }

    private static boolean isFieldUpdatable(FieldType fieldType, FieldType fieldType2) {
        return (fieldType == fieldType2 || fieldType.isForeignCollection() || fieldType.isReadOnly()) ? false : true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int update(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws IllegalAccessException, SQLException, IllegalArgumentException, InvocationTargetException {
        T t2;
        SQLException sQLException;
        Object objMoveToNextValue;
        ObjectCache objectCache2;
        try {
            int i = 0;
            if (this.argFieldTypes.length <= 1) {
                return 0;
            }
            Object[] fieldObjects = getFieldObjects(t);
            FieldType fieldType = this.versionFieldType;
            if (fieldType != null) {
                try {
                    objMoveToNextValue = this.versionFieldType.moveToNextValue(fieldType.extractJavaFieldValue(t));
                    fieldObjects[this.versionFieldTypeIndex] = this.versionFieldType.convertJavaFieldToSqlArgValue(objMoveToNextValue);
                } catch (SQLException e) {
                    sQLException = e;
                    t2 = t;
                    throw new SQLException("Unable to run update stmt on object " + t2 + ": " + this.statement, sQLException);
                }
            } else {
                objMoveToNextValue = null;
            }
            Object obj = objMoveToNextValue;
            int iUpdate = databaseConnection.update(this.statement, fieldObjects, this.argFieldTypes);
            if (iUpdate > 0) {
                if (obj != null) {
                    t2 = t;
                    try {
                        this.versionFieldType.assignField(this.connectionSource, t2, obj, false, null);
                    } catch (SQLException e2) {
                        e = e2;
                        sQLException = e;
                        throw new SQLException("Unable to run update stmt on object " + t2 + ": " + this.statement, sQLException);
                    }
                } else {
                    t2 = t;
                }
                if (objectCache != 0) {
                    Object obj2 = objectCache.get(this.clazz, this.idField.extractJavaFieldValue(t2));
                    if (obj2 != null && obj2 != t2) {
                        FieldType[] fieldTypes = this.tableInfo.getFieldTypes();
                        int length = fieldTypes.length;
                        ObjectCache objectCache3 = objectCache;
                        while (i < length) {
                            FieldType fieldType2 = fieldTypes[i];
                            if (fieldType2 != this.idField) {
                                objectCache2 = objectCache3;
                                fieldType2.assignField(this.connectionSource, obj2, fieldType2.extractJavaFieldValue(t2), false, objectCache2);
                            } else {
                                objectCache2 = objectCache3;
                            }
                            i++;
                            objectCache3 = objectCache2;
                        }
                    }
                }
            } else {
                t2 = t;
            }
            BaseMappedStatement.logger.debug("update data with statement '{}' and {} args, changed {} rows", this.statement, Integer.valueOf(fieldObjects.length), Integer.valueOf(iUpdate));
            if (fieldObjects.length > 0) {
                BaseMappedStatement.logger.trace("update arguments: {}", (Object) fieldObjects);
            }
            return iUpdate;
        } catch (SQLException e3) {
            e = e3;
            t2 = t;
        }
    }
}
