package com.j256.ormlite.db;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.j256.ormlite.field.DataPersister;
import com.j256.ormlite.field.FieldConverter;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.DatabaseTableConfig;
import java.sql.Driver;
import java.sql.SQLException;
import java.util.List;
import java.util.Locale;

/* loaded from: classes2.dex */
public abstract class BaseDatabaseType implements DatabaseType {
    protected static String DEFAULT_SEQUENCE_SUFFIX = "_id_seq";
    protected Driver driver;
    protected Logger logger = LoggerFactory.getLogger(getClass());

    /* renamed from: com.j256.ormlite.db.BaseDatabaseType$1, reason: invalid class name */
    public static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$j256$ormlite$field$SqlType;

        static {
            int[] iArr = new int[SqlType.values().length];
            $SwitchMap$com$j256$ormlite$field$SqlType = iArr;
            try {
                iArr[SqlType.STRING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.LONG_STRING.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BOOLEAN.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.DATE.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.CHAR.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BYTE.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BYTE_ARRAY.ordinal()] = 7;
            } catch (NoSuchFieldError unused7) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.SHORT.ordinal()] = 8;
            } catch (NoSuchFieldError unused8) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.INTEGER.ordinal()] = 9;
            } catch (NoSuchFieldError unused9) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.LONG.ordinal()] = 10;
            } catch (NoSuchFieldError unused10) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.FLOAT.ordinal()] = 11;
            } catch (NoSuchFieldError unused11) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.DOUBLE.ordinal()] = 12;
            } catch (NoSuchFieldError unused12) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.SERIALIZABLE.ordinal()] = 13;
            } catch (NoSuchFieldError unused13) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.BIG_DECIMAL.ordinal()] = 14;
            } catch (NoSuchFieldError unused14) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.UUID.ordinal()] = 15;
            } catch (NoSuchFieldError unused15) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.OTHER.ordinal()] = 16;
            } catch (NoSuchFieldError unused16) {
            }
            try {
                $SwitchMap$com$j256$ormlite$field$SqlType[SqlType.UNKNOWN.ordinal()] = 17;
            } catch (NoSuchFieldError unused17) {
            }
        }
    }

    private void addSingleUnique(StringBuilder sb, FieldType fieldType, List<String> list, List<String> list2) {
        StringBuilder sbU = d0.u(" UNIQUE (");
        appendEscapedEntityName(sbU, fieldType.getColumnName());
        sbU.append(')');
        list.add(sbU.toString());
    }

    private void appendCanBeNull(StringBuilder sb, FieldType fieldType) {
    }

    private void appendDefaultValue(StringBuilder sb, FieldType fieldType, Object obj) {
        if (fieldType.isEscapedDefaultValue()) {
            appendEscapedWord(sb, obj.toString());
        } else {
            sb.append(obj);
        }
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void addPrimaryKeySql(FieldType[] fieldTypeArr, List<String> list, List<String> list2, List<String> list3, List<String> list4) {
        StringBuilder sbL = null;
        for (FieldType fieldType : fieldTypeArr) {
            if ((!fieldType.isGeneratedId() || generatedIdSqlAtEnd() || fieldType.isSelfGeneratedId()) && fieldType.isId()) {
                if (sbL == null) {
                    sbL = B.l(48, "PRIMARY KEY (");
                } else {
                    sbL.append(',');
                }
                appendEscapedEntityName(sbL, fieldType.getColumnName());
            }
        }
        if (sbL != null) {
            sbL.append(") ");
            list.add(sbL.toString());
        }
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void addUniqueComboSql(FieldType[] fieldTypeArr, List<String> list, List<String> list2, List<String> list3, List<String> list4) {
        StringBuilder sbL = null;
        for (FieldType fieldType : fieldTypeArr) {
            if (fieldType.isUniqueCombo()) {
                if (sbL == null) {
                    sbL = B.l(48, "UNIQUE (");
                } else {
                    sbL.append(',');
                }
                appendEscapedEntityName(sbL, fieldType.getColumnName());
            }
        }
        if (sbL != null) {
            sbL.append(") ");
            list.add(sbL.toString());
        }
    }

    public void appendBigDecimalNumericType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("NUMERIC");
    }

    public void appendBooleanType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("BOOLEAN");
    }

    public void appendByteArrayType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("BLOB");
    }

    public void appendByteType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("TINYINT");
    }

    public void appendCharType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("CHAR");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendColumnArg(String str, StringBuilder sb, FieldType fieldType, List<String> list, List<String> list2, List<String> list3, List<String> list4) throws SQLException {
        appendEscapedEntityName(sb, fieldType.getColumnName());
        sb.append(' ');
        DataPersister dataPersister = fieldType.getDataPersister();
        int width = fieldType.getWidth();
        if (width == 0) {
            width = dataPersister.getDefaultWidth();
        }
        switch (AnonymousClass1.$SwitchMap$com$j256$ormlite$field$SqlType[dataPersister.getSqlType().ordinal()]) {
            case 1:
                appendStringType(sb, fieldType, width);
                break;
            case 2:
                appendLongStringType(sb, fieldType, width);
                break;
            case 3:
                appendBooleanType(sb, fieldType, width);
                break;
            case 4:
                appendDateType(sb, fieldType, width);
                break;
            case 5:
                appendCharType(sb, fieldType, width);
                break;
            case 6:
                appendByteType(sb, fieldType, width);
                break;
            case 7:
                appendByteArrayType(sb, fieldType, width);
                break;
            case 8:
                appendShortType(sb, fieldType, width);
                break;
            case 9:
                appendIntegerType(sb, fieldType, width);
                break;
            case 10:
                appendLongType(sb, fieldType, width);
                break;
            case 11:
                appendFloatType(sb, fieldType, width);
                break;
            case 12:
                appendDoubleType(sb, fieldType, width);
                break;
            case 13:
                appendSerializableType(sb, fieldType, width);
                break;
            case 14:
                appendBigDecimalNumericType(sb, fieldType, width);
                break;
            case 15:
                appendUuidNativeType(sb, fieldType, width);
                break;
            case 16:
                String sqlOtherType = dataPersister.getSqlOtherType();
                if (sqlOtherType != null) {
                    sb.append(sqlOtherType);
                    break;
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown SQL-type " + dataPersister.getSqlType());
        }
        sb.append(' ');
        if (fieldType.isGeneratedIdSequence() && !fieldType.isSelfGeneratedId()) {
            configureGeneratedIdSequence(sb, fieldType, list2, list, list4);
        } else if (fieldType.isGeneratedId() && !fieldType.isSelfGeneratedId()) {
            configureGeneratedId(str, sb, fieldType, list2, list3, list, list4);
        } else if (fieldType.isId()) {
            configureId(sb, fieldType, list2, list, list4);
        }
        if (fieldType.isGeneratedId()) {
            return;
        }
        Object defaultValue = fieldType.getDefaultValue();
        if (defaultValue != null) {
            sb.append("DEFAULT ");
            appendDefaultValue(sb, fieldType, defaultValue);
            sb.append(' ');
        }
        if (fieldType.isCanBeNull()) {
            appendCanBeNull(sb, fieldType);
        } else {
            sb.append("NOT NULL ");
        }
        if (fieldType.isUnique()) {
            addSingleUnique(sb, fieldType, list, list3);
        }
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendCreateSchemaSuffix(StringBuilder sb) {
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendCreateTableSuffix(StringBuilder sb) {
    }

    public void appendDateType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("TIMESTAMP");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendDeleteLimitValue(StringBuilder sb, long j) {
        appendLimitValue(sb, j, null);
    }

    public void appendDoubleType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("DOUBLE PRECISION");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendEscapedEntityName(StringBuilder sb, String str) {
        sb.append('`');
        int iIndexOf = str.indexOf(46);
        if (iIndexOf > 0) {
            sb.append(str.substring(0, iIndexOf));
            sb.append("`.`");
            sb.append(str.substring(iIndexOf + 1));
        } else {
            sb.append(str);
        }
        sb.append('`');
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendEscapedWord(StringBuilder sb, String str) {
        sb.append('\'');
        sb.append(str);
        sb.append('\'');
    }

    public void appendFloatType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("FLOAT");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendInsertNoColumns(StringBuilder sb) {
        sb.append("() VALUES ()");
    }

    public void appendIntegerType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("INTEGER");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendLimitValue(StringBuilder sb, long j, Long l) {
        sb.append("LIMIT ");
        sb.append(j);
        sb.append(' ');
    }

    public void appendLongStringType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("TEXT");
    }

    public void appendLongType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("BIGINT");
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendOffsetValue(StringBuilder sb, long j) {
        sb.append("OFFSET ");
        sb.append(j);
        sb.append(' ');
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendSelectNextValFromSequence(StringBuilder sb, String str) {
    }

    public void appendSerializableType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("BLOB");
    }

    public void appendShortType(StringBuilder sb, FieldType fieldType, int i) {
        sb.append("SMALLINT");
    }

    public void appendStringType(StringBuilder sb, FieldType fieldType, int i) {
        if (!isVarcharFieldWidthSupported()) {
            sb.append("VARCHAR");
            return;
        }
        sb.append("VARCHAR(");
        sb.append(i);
        sb.append(')');
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void appendUpdateLimitValue(StringBuilder sb, long j) {
        appendLimitValue(sb, j, null);
    }

    public void appendUuidNativeType(StringBuilder sb, FieldType fieldType, int i) {
        throw new UnsupportedOperationException("UUID is not supported by this database type");
    }

    public void configureGeneratedId(String str, StringBuilder sb, FieldType fieldType, List<String> list, List<String> list2, List<String> list3, List<String> list4) {
        throw new IllegalStateException("GeneratedId is not supported by database " + getDatabaseName() + " for field " + fieldType);
    }

    public void configureGeneratedIdSequence(StringBuilder sb, FieldType fieldType, List<String> list, List<String> list2, List<String> list3) throws SQLException {
        throw new SQLException("GeneratedIdSequence is not supported by database " + getDatabaseName() + " for field " + fieldType);
    }

    public void configureId(StringBuilder sb, FieldType fieldType, List<String> list, List<String> list2, List<String> list3) {
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String downCaseString(String str, boolean z) {
        return z ? str.toLowerCase(Locale.ENGLISH) : str.toLowerCase();
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void dropColumnArg(FieldType fieldType, List<String> list, List<String> list2) {
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public <T> DatabaseTableConfig<T> extractDatabaseTableConfig(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        return null;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String generateIdSequenceName(String str, FieldType fieldType) {
        StringBuilder sbU = d0.u(str);
        sbU.append(DEFAULT_SEQUENCE_SUFFIX);
        String string = sbU.toString();
        return isSequenceNamesMustBeLowerCase() ? downCaseString(string, true) : isEntityNamesMustBeUpCase() ? upCaseEntityName(string) : string;
    }

    public boolean generatedIdSqlAtEnd() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String getCommentLinePrefix() {
        return "-- ";
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public DataPersister getDataPersister(DataPersister dataPersister, FieldType fieldType) {
        return dataPersister;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public abstract /* synthetic */ String getDatabaseName();

    public String[] getDriverClassNames() {
        return new String[0];
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public FieldConverter getFieldConverter(DataPersister dataPersister, FieldType fieldType) {
        return dataPersister;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String getPingStatement() {
        return "SELECT 1";
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isAllowGeneratedIdInsertSupported() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isBatchUseTransaction() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateIfNotExistsSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateIndexIfNotExistsSupported() {
        return isCreateIfNotExistsSupported();
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateSchemaIfNotExistsSupported() {
        return isCreateIfNotExistsSupported();
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateSchemaReturnsNegative() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateSchemaReturnsZero() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateTableReturnsNegative() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isCreateTableReturnsZero() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public abstract /* synthetic */ boolean isDatabaseUrlThisType(String str, String str2);

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isEntityNamesMustBeUpCase() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isIdSequenceNeeded() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitAfterDeleteSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitAfterSelect() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitAfterUpdateSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitDeleteAtEndSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitSqlSupported() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isLimitUpdateAtEndSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isNestedSavePointsSupported() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isOffsetLimitArgument() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isOffsetSqlSupported() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isSelectSequenceBeforeInsert() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isSequenceNamesMustBeLowerCase() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isTruncateSupported() {
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean isVarcharFieldWidthSupported() {
        return true;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public boolean loadDriver() throws ClassNotFoundException {
        for (String str : getDriverClassNames()) {
            if (str != null) {
                try {
                    Class.forName(str);
                    return true;
                } catch (ClassNotFoundException e) {
                    this.logger.warn("Driver class was not found for " + getDatabaseName() + " database.  Class not found: " + str, e);
                }
            }
        }
        return false;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public void setDriver(Driver driver) {
        this.driver = driver;
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String upCaseEntityName(String str) {
        return upCaseString(str, true);
    }

    @Override // com.j256.ormlite.db.DatabaseType
    public String upCaseString(String str, boolean z) {
        return z ? str.toUpperCase(Locale.ENGLISH) : str.toUpperCase();
    }
}
