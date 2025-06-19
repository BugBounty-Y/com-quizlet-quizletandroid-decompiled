package com.j256.ormlite.field;

import com.j256.ormlite.support.DatabaseResults;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public abstract class BaseFieldConverter implements FieldConverter {
    @Override // com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ SqlType getSqlType();

    @Override // com.j256.ormlite.field.FieldConverter
    public boolean isStreamType() {
        return false;
    }

    @Override // com.j256.ormlite.field.FieldConverter
    public Object javaToSqlArg(FieldType fieldType, Object obj) throws SQLException {
        return obj;
    }

    @Override // com.j256.ormlite.field.FieldConverter
    public Object makeConfigObject(FieldType fieldType) throws SQLException {
        return null;
    }

    @Override // com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object parseDefaultString(FieldType fieldType, String str) throws SQLException;

    @Override // com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object resultStringToJava(FieldType fieldType, String str, int i) throws SQLException;

    @Override // com.j256.ormlite.field.FieldConverter
    public Object resultToJava(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException {
        Object objResultToSqlArg = resultToSqlArg(fieldType, databaseResults, i);
        if (objResultToSqlArg == null) {
            return null;
        }
        return sqlArgToJava(fieldType, objResultToSqlArg, i);
    }

    @Override // com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException;

    @Override // com.j256.ormlite.field.FieldConverter
    public Object sqlArgToJava(FieldType fieldType, Object obj, int i) throws SQLException {
        return obj;
    }
}
