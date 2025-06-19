package com.j256.ormlite.field.types;

import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.support.DatabaseResults;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;

/* loaded from: classes2.dex */
public abstract class BaseDateType extends BaseDataType {
    private static final DateStringFormatConfig DEFAULT_DATE_FORMAT_CONFIG = new DateStringFormatConfig("yyyy-MM-dd HH:mm:ss.SSSSSS");
    private static final DateStringFormatConfig NO_MILLIS_DATE_FORMAT_CONFIG = new DateStringFormatConfig("yyyy-MM-dd HH:mm:ss");

    public BaseDateType(SqlType sqlType, Class<?>[] clsArr) {
        super(sqlType, clsArr);
    }

    private static DateFormat conditionalFormat(DateStringFormatConfig dateStringFormatConfig, String str) {
        return (dateStringFormatConfig != DEFAULT_DATE_FORMAT_CONFIG || str.indexOf(46) >= 0) ? dateStringFormatConfig.getDateFormat() : NO_MILLIS_DATE_FORMAT_CONFIG.getDateFormat();
    }

    public static DateStringFormatConfig convertDateStringConfig(FieldType fieldType, DateStringFormatConfig dateStringFormatConfig) {
        DateStringFormatConfig dateStringFormatConfig2;
        return (fieldType == null || (dateStringFormatConfig2 = (DateStringFormatConfig) fieldType.getDataTypeConfigObj()) == null) ? dateStringFormatConfig : dateStringFormatConfig2;
    }

    public static String normalizeDateString(DateStringFormatConfig dateStringFormatConfig, String str) throws ParseException {
        DateFormat dateFormatConditionalFormat = conditionalFormat(dateStringFormatConfig, str);
        return dateFormatConditionalFormat.format(dateFormatConditionalFormat.parse(str));
    }

    public static Date parseDateString(DateStringFormatConfig dateStringFormatConfig, String str) throws ParseException {
        return conditionalFormat(dateStringFormatConfig, str).parse(str);
    }

    public DateStringFormatConfig getDefaultDateFormatConfig() {
        return DEFAULT_DATE_FORMAT_CONFIG;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isValidForField(Field field) {
        return field.getType() == Date.class;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public boolean isValidForVersion() {
        return true;
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.DataPersister
    public Object moveToNextValue(Object obj) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        if (obj != null && jCurrentTimeMillis == ((Date) obj).getTime()) {
            return new Date(jCurrentTimeMillis + 1);
        }
        return new Date(jCurrentTimeMillis);
    }

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object parseDefaultString(FieldType fieldType, String str) throws SQLException;

    @Override // com.j256.ormlite.field.types.BaseDataType, com.j256.ormlite.field.BaseFieldConverter, com.j256.ormlite.field.FieldConverter
    public abstract /* synthetic */ Object resultToSqlArg(FieldType fieldType, DatabaseResults databaseResults, int i) throws SQLException;

    public BaseDateType(SqlType sqlType) {
        super(sqlType);
    }
}
