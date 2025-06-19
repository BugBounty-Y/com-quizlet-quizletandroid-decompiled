package com.j256.ormlite.field.types;

import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.support.DatabaseResults;
import java.sql.SQLException;
import java.util.Currency;

/* loaded from: classes2.dex */
public class CurrencyType extends BaseDataType {
    public static int DEFAULT_WIDTH = 30;
    private static final CurrencyType singleTon = new CurrencyType();

    public CurrencyType() {
        super(SqlType.STRING, new Class[]{Currency.class});
    }

    public static CurrencyType getSingleton() {
        return singleTon;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public int getDefaultWidth() {
        return DEFAULT_WIDTH;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isAppropriateId() {
        return false;
    }

    @Override // com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object javaToSqlArg(FieldType fieldType, Object obj) {
        return ((Currency) obj).getCurrencyCode();
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object parseDefaultString(FieldType fieldType, String str) throws SQLException {
        try {
            return Currency.getInstance(str).getCurrencyCode();
        } catch (IllegalArgumentException e) {
            throw new SQLException("Problems with field " + fieldType + " parsing default Currency '", e);
        }
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException {
        return databaseResults.getString(i);
    }

    @Override // com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object sqlArgToJava(FieldType fieldType, Object obj, int i) throws SQLException {
        String str = (String) obj;
        try {
            return Currency.getInstance(str);
        } catch (IllegalArgumentException e) {
            throw new SQLException("Problems with column " + i + " parsing Currency '" + str + "'", e);
        }
    }

    public CurrencyType(SqlType sqlType, Class<?>[] clsArr) {
        super(sqlType, clsArr);
    }
}
