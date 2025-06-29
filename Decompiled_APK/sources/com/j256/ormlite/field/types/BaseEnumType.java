package com.j256.ormlite.field.types;

import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.support.DatabaseResults;
import java.lang.reflect.Field;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public abstract class BaseEnumType extends BaseDataType {
    public BaseEnumType(SqlType sqlType, Class<?>[] clsArr) {
        super(sqlType, clsArr);
    }

    public static Enum<?> enumVal(FieldType fieldType, Object obj, Enum<?> r3, Enum<?> r4) throws SQLException {
        if (r3 != null) {
            return r3;
        }
        if (r4 != null) {
            return r4;
        }
        throw new SQLException("Cannot get enum value of '" + obj + "' for field " + fieldType);
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isValidForField(Field field) {
        return field.getType().isEnum();
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object parseDefaultString(FieldType fieldType, String str) throws SQLException;

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException;

    public BaseEnumType(SqlType sqlType) {
        super(sqlType);
    }
}
