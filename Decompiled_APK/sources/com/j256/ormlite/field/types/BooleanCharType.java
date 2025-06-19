package com.j256.ormlite.field.types;

import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.support.DatabaseResults;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class BooleanCharType extends BooleanType {
    private static final String DEFAULT_TRUE_FALSE_FORMAT = "10";
    private static final BooleanCharType singleTon = new BooleanCharType();

    public BooleanCharType() {
        super(SqlType.CHAR);
    }

    public static BooleanCharType getSingleton() {
        return singleTon;
    }

    @Override // com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object javaToSqlArg(FieldType fieldType, Object obj) {
        String str = (String) fieldType.getDataTypeConfigObj();
        if (str == null || str.length() < 2) {
            str = DEFAULT_TRUE_FALSE_FORMAT;
        }
        return Character.valueOf(str.charAt(((Boolean) obj).booleanValue() ? 0 : 1));
    }

    @Override // com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object makeConfigObject(FieldType fieldType) throws SQLException {
        String format = fieldType.getFormat();
        if (format == null) {
            return DEFAULT_TRUE_FALSE_FORMAT;
        }
        if (format.length() != 2 || format.charAt(0) == format.charAt(1)) {
            throw new SQLException("Invalid boolean format must have 2 different characters that represent true/false like \"10\" or \"tf\": ".concat(format));
        }
        return format;
    }

    @Override // com.j256.ormlite.field.types.BooleanObjectType, com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object parseDefaultString(FieldType fieldType, String str) {
        return javaToSqlArg(fieldType, Boolean.valueOf(Boolean.parseBoolean(str)));
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object resultStringToJava(FieldType fieldType, String str, int i) {
        return str.length() == 0 ? Boolean.FALSE : sqlArgToJava(fieldType, Character.valueOf(str.charAt(0)), i);
    }

    @Override // com.j256.ormlite.field.types.BooleanObjectType, com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException {
        return Character.valueOf(databaseResults.getChar(i));
    }

    @Override // com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object sqlArgToJava(FieldType fieldType, Object obj, int i) {
        String str = (String) fieldType.getDataTypeConfigObj();
        if (str == null || str.length() < 2) {
            str = DEFAULT_TRUE_FALSE_FORMAT;
        }
        return ((Character) obj).charValue() == str.charAt(0) ? Boolean.TRUE : Boolean.FALSE;
    }
}
