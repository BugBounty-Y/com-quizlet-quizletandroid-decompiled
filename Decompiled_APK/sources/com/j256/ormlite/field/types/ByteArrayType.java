package com.j256.ormlite.field.types;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.support.DatabaseResults;
import java.io.UnsupportedEncodingException;
import java.sql.SQLException;
import java.util.Arrays;

/* loaded from: classes2.dex */
public class ByteArrayType extends BaseDataType {
    private static final ByteArrayType singleTon = new ByteArrayType();

    private ByteArrayType() {
        super(SqlType.BYTE_ARRAY);
    }

    private Object getBytesImpl(FieldType fieldType, String str) throws SQLException {
        if (fieldType == null || fieldType.getFormat() == null) {
            return str.getBytes();
        }
        try {
            return str.getBytes(fieldType.getFormat());
        } catch (UnsupportedEncodingException e) {
            throw new SQLException(AbstractC0147y.d("Could not convert default string: ", str), e);
        }
    }

    public static ByteArrayType getSingleton() {
        return singleTon;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean dataIsEqual(Object obj, Object obj2) {
        if (obj == null) {
            return obj2 == null;
        }
        if (obj2 == null) {
            return false;
        }
        return Arrays.equals((byte[]) obj, (byte[]) obj2);
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public Class<?> getPrimaryClass() {
        return byte[].class;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isAppropriateId() {
        return true;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isArgumentHolderRequired() {
        return true;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object parseDefaultString(FieldType fieldType, String str) throws SQLException {
        if (str == null) {
            return null;
        }
        return getBytesImpl(fieldType, str);
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object resultStringToJava(FieldType fieldType, String str, int i) throws SQLException {
        return getBytesImpl(fieldType, str);
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException {
        return databaseResults.getBytes(i);
    }

    public ByteArrayType(SqlType sqlType, Class<?>[] clsArr) {
        super(sqlType, clsArr);
    }
}
