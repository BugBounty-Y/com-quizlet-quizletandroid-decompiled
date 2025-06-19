package com.j256.ormlite.field;

import android.support.v4.media.session.a;
import androidx.compose.ui.node.B;
import com.j256.ormlite.dao.BaseForeignCollection;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.dao.EagerForeignCollection;
import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.dao.LazyForeignCollection;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.dao.StreamableLazyForeignCollection;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.types.SerializableType;
import com.j256.ormlite.field.types.VoidType;
import com.j256.ormlite.logger.Level;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.stmt.mapped.MappedQueryForFieldEq;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.DatabaseResults;
import com.j256.ormlite.table.DatabaseTableConfig;
import com.j256.ormlite.table.TableInfo;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Map;

/* loaded from: classes2.dex */
public class FieldType {
    private static boolean DEFAULT_VALUE_BOOLEAN = false;
    private static byte DEFAULT_VALUE_BYTE = 0;
    private static char DEFAULT_VALUE_CHAR = 0;
    private static double DEFAULT_VALUE_DOUBLE = 0.0d;
    private static float DEFAULT_VALUE_FLOAT = 0.0f;
    private static int DEFAULT_VALUE_INT = 0;
    private static long DEFAULT_VALUE_LONG = 0;
    private static short DEFAULT_VALUE_SHORT = 0;
    public static final String FOREIGN_ID_FIELD_SUFFIX = "_id";
    private static boolean hasStreamClass;
    private final String columnName;
    private DataPersister dataPersister;
    private Object dataTypeConfigObj;
    private Object defaultValue;
    private final Field field;
    private final DatabaseFieldConfig fieldConfig;
    private FieldConverter fieldConverter;
    private final Method fieldGetMethod;
    private final Method fieldSetMethod;
    private Dao<?, ?> foreignDao;
    private FieldType foreignFieldType;
    private FieldType foreignIdField;
    private FieldType foreignRefField;
    private final String generatedIdSequence;
    private final boolean isGeneratedId;
    private final boolean isId;
    private MappedQueryForFieldEq<?, ?> mappedQueryForForeignField;
    private final Class<?> parentClass;
    private final String tableName;
    private static final ThreadLocal<LevelCounters> threadLevelCounters = new ThreadLocal<>();
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) FieldType.class);

    public static class LevelCounters {
        int autoRefreshLevel;
        int autoRefreshLevelMax;
        int foreignCollectionLevel;
        int foreignCollectionLevelMax;
    }

    static {
        try {
            hasStreamClass = true;
        } catch (Exception unused) {
            hasStreamClass = false;
        }
    }

    public FieldType(DatabaseType databaseType, String str, Field field, DatabaseFieldConfig databaseFieldConfig, Class<?> cls) throws IllegalAccessException, SQLException, SecurityException, IllegalArgumentException, InvocationTargetException {
        DataPersister dataPersister;
        this.tableName = str;
        this.field = field;
        this.parentClass = cls;
        databaseFieldConfig.postProcess();
        Class<?> type = field.getType();
        if (databaseFieldConfig.getDataPersister() == null) {
            Class<? extends DataPersister> persisterClass = databaseFieldConfig.getPersisterClass();
            if (persisterClass == null || persisterClass == VoidType.class) {
                dataPersister = DataPersisterManager.lookupForField(field);
            } else {
                try {
                    try {
                        Object objInvoke = persisterClass.getDeclaredMethod("getSingleton", null).invoke(null, null);
                        if (objInvoke == null) {
                            throw new SQLException(B.d(persisterClass, "Static getSingleton method should not return null on class "));
                        }
                        try {
                            dataPersister = (DataPersister) objInvoke;
                        } catch (Exception e) {
                            throw new SQLException(B.d(persisterClass, "Could not cast result of static getSingleton method to DataPersister from class "), e);
                        }
                    } catch (InvocationTargetException e2) {
                        throw new SQLException(B.d(persisterClass, "Could not run getSingleton method on class "), e2.getTargetException());
                    } catch (Exception e3) {
                        throw new SQLException(B.d(persisterClass, "Could not run getSingleton method on class "), e3);
                    }
                } catch (Exception e4) {
                    throw new SQLException(B.d(persisterClass, "Could not find getSingleton static method on class "), e4);
                }
            }
        } else {
            dataPersister = databaseFieldConfig.getDataPersister();
            if (!dataPersister.isValidForField(field)) {
                StringBuilder sb = new StringBuilder("Field class ");
                sb.append(type.getName());
                sb.append(" for field ");
                sb.append(this);
                sb.append(" is not valid for type ");
                sb.append(dataPersister);
                Class<?> primaryClass = dataPersister.getPrimaryClass();
                if (primaryClass != null) {
                    sb.append(", maybe should be ");
                    sb.append(primaryClass);
                }
                throw new IllegalArgumentException(sb.toString());
            }
        }
        String foreignColumnName = databaseFieldConfig.getForeignColumnName();
        String name = field.getName();
        if (databaseFieldConfig.isForeign() || databaseFieldConfig.isForeignAutoRefresh() || foreignColumnName != null) {
            if (dataPersister != null && dataPersister.isPrimitive()) {
                throw new IllegalArgumentException("Field " + this + " is a primitive class " + type + " but marked as foreign");
            }
            name = foreignColumnName == null ? a.k(name, FOREIGN_ID_FIELD_SUFFIX) : a.l(name, "_", foreignColumnName);
            if (ForeignCollection.class.isAssignableFrom(type)) {
                throw new SQLException("Field '" + field.getName() + "' in class " + type + "' should use the @ForeignCollectionField annotation not foreign=true");
            }
        } else if (databaseFieldConfig.isForeignCollection()) {
            if (type != Collection.class && !ForeignCollection.class.isAssignableFrom(type)) {
                throw new SQLException("Field class for '" + field.getName() + "' must be of class ForeignCollection or Collection.");
            }
            Type genericType = field.getGenericType();
            if (!(genericType instanceof ParameterizedType)) {
                throw new SQLException("Field class for '" + field.getName() + "' must be a parameterized Collection.");
            }
            if (((ParameterizedType) genericType).getActualTypeArguments().length == 0) {
                throw new SQLException("Field class for '" + field.getName() + "' must be a parameterized Collection with at least 1 type.");
            }
        } else if (dataPersister == null && !databaseFieldConfig.isForeignCollection()) {
            if (byte[].class.isAssignableFrom(type)) {
                throw new SQLException("ORMLite does not know how to store " + type + " for field '" + field.getName() + "'. byte[] fields must specify dataType=DataType.BYTE_ARRAY or SERIALIZABLE");
            }
            if (!Serializable.class.isAssignableFrom(type)) {
                throw new IllegalArgumentException("ORMLite does not know how to store " + type + " for field " + field.getName() + ". Use another class or a custom persister.");
            }
            if (!databaseFieldConfig.isJavaxEntity()) {
                throw new SQLException("ORMLite does not know how to store " + type + " for field '" + field.getName() + "'.  Use another class, custom persister, or to serialize it use dataType=DataType.SERIALIZABLE");
            }
            dataPersister = SerializableType.getSingleton();
        }
        if (databaseFieldConfig.getColumnName() == null) {
            this.columnName = name;
        } else {
            this.columnName = databaseFieldConfig.getColumnName();
        }
        this.fieldConfig = databaseFieldConfig;
        if (databaseFieldConfig.isId()) {
            if (databaseFieldConfig.isGeneratedId() || databaseFieldConfig.getGeneratedIdSequence() != null) {
                throw new IllegalArgumentException("Must specify one of id, generatedId, and generatedIdSequence with " + field.getName());
            }
            this.isId = true;
            this.isGeneratedId = false;
            this.generatedIdSequence = null;
        } else if (databaseFieldConfig.isGeneratedId()) {
            if (databaseFieldConfig.getGeneratedIdSequence() != null) {
                throw new IllegalArgumentException("Must specify one of id, generatedId, and generatedIdSequence with " + field.getName());
            }
            this.isId = true;
            this.isGeneratedId = true;
            if (databaseType.isIdSequenceNeeded()) {
                this.generatedIdSequence = databaseType.generateIdSequenceName(str, this);
            } else {
                this.generatedIdSequence = null;
            }
        } else if (databaseFieldConfig.getGeneratedIdSequence() != null) {
            this.isId = true;
            this.isGeneratedId = true;
            String generatedIdSequence = databaseFieldConfig.getGeneratedIdSequence();
            this.generatedIdSequence = databaseType.isEntityNamesMustBeUpCase() ? databaseType.upCaseEntityName(generatedIdSequence) : generatedIdSequence;
        } else {
            this.isId = false;
            this.isGeneratedId = false;
            this.generatedIdSequence = null;
        }
        if (this.isId && databaseFieldConfig.isForeign()) {
            throw new IllegalArgumentException("Id field " + field.getName() + " cannot also be a foreign object");
        }
        if (databaseFieldConfig.isUseGetSet()) {
            this.fieldGetMethod = DatabaseFieldConfig.findGetMethod(field, databaseType, true);
            this.fieldSetMethod = DatabaseFieldConfig.findSetMethod(field, databaseType, true);
        } else {
            if (!field.isAccessible()) {
                try {
                    field.setAccessible(true);
                } catch (SecurityException unused) {
                    throw new IllegalArgumentException("Could not open access to field " + field.getName() + ".  You may have to set useGetSet=true to fix.");
                }
            }
            this.fieldGetMethod = null;
            this.fieldSetMethod = null;
        }
        if (databaseFieldConfig.isAllowGeneratedIdInsert() && !databaseFieldConfig.isGeneratedId()) {
            throw new IllegalArgumentException("Field " + field.getName() + " must be a generated-id if allowGeneratedIdInsert = true");
        }
        if (databaseFieldConfig.getForeignColumnName() != null && !databaseFieldConfig.isForeign()) {
            throw new IllegalArgumentException("Field " + field.getName() + " must have foreign = true if foreignColumnName is set");
        }
        if (databaseFieldConfig.isForeignAutoRefresh() && !databaseFieldConfig.isForeign()) {
            throw new IllegalArgumentException("Field " + field.getName() + " must have foreign = true if foreignAutoRefresh = true");
        }
        if (databaseFieldConfig.isForeignAutoCreate() && !databaseFieldConfig.isForeign()) {
            throw new IllegalArgumentException("Field " + field.getName() + " must have foreign = true if foreignAutoCreate = true");
        }
        if (!databaseFieldConfig.isVersion() || (dataPersister != null && dataPersister.isValidForVersion())) {
            assignDataType(databaseType, dataPersister);
            return;
        }
        throw new IllegalArgumentException("Field " + field.getName() + " is not a valid type to be a version field");
    }

    private void assignDataType(DatabaseType databaseType, DataPersister dataPersister) throws SQLException {
        DataPersister dataPersister2 = databaseType.getDataPersister(dataPersister, this);
        this.dataPersister = dataPersister2;
        if (dataPersister2 == null) {
            if (this.fieldConfig.isForeign() || this.fieldConfig.isForeignCollection()) {
                return;
            }
            throw new SQLException("Data persister for field " + this + " is null but the field is not a foreign or foreignCollection");
        }
        this.fieldConverter = databaseType.getFieldConverter(dataPersister2, this);
        if (this.isGeneratedId && !dataPersister2.isValidGeneratedType()) {
            StringBuilder sb = new StringBuilder("Generated-id field '");
            sb.append(this.field.getName());
            sb.append("' in ");
            sb.append(this.field.getDeclaringClass().getSimpleName());
            sb.append(" can't be type ");
            sb.append(dataPersister2.getSqlType());
            sb.append(".  Must be one of: ");
            for (DataType dataType : DataType.values()) {
                DataPersister dataPersister3 = dataType.getDataPersister();
                if (dataPersister3 != null && dataPersister3.isValidGeneratedType()) {
                    sb.append(dataType);
                    sb.append(' ');
                }
            }
            throw new IllegalArgumentException(sb.toString());
        }
        if (this.fieldConfig.isThrowIfNull() && !dataPersister2.isPrimitive()) {
            throw new SQLException("Field " + this.field.getName() + " must be a primitive if set with throwIfNull");
        }
        if (this.isId && !dataPersister2.isAppropriateId()) {
            throw new SQLException("Field '" + this.field.getName() + "' is of data type " + dataPersister2 + " which cannot be the ID field");
        }
        this.dataTypeConfigObj = this.fieldConverter.makeConfigObject(this);
        String defaultValue = this.fieldConfig.getDefaultValue();
        if (defaultValue == null) {
            this.defaultValue = null;
            return;
        }
        if (!this.isGeneratedId) {
            this.defaultValue = this.fieldConverter.parseDefaultString(this, defaultValue);
            return;
        }
        throw new SQLException("Field '" + this.field.getName() + "' cannot be a generatedId and have a default value '" + defaultValue + "'");
    }

    public static FieldType createFieldType(DatabaseType databaseType, String str, Field field, Class<?> cls) throws SQLException {
        DatabaseFieldConfig databaseFieldConfigFromField = DatabaseFieldConfig.fromField(databaseType, str, field);
        if (databaseFieldConfigFromField == null) {
            return null;
        }
        return new FieldType(databaseType, str, field, databaseFieldConfigFromField, cls);
    }

    private Object createForeignObject(ConnectionSource connectionSource, Object obj, ObjectCache objectCache) throws SQLException {
        ThreadLocal<LevelCounters> threadLocal = threadLevelCounters;
        LevelCounters levelCounters = threadLocal.get();
        if (levelCounters == null) {
            if (!this.fieldConfig.isForeignAutoRefresh()) {
                return createForeignShell(connectionSource, obj, objectCache);
            }
            levelCounters = new LevelCounters();
            threadLocal.set(levelCounters);
        }
        if (levelCounters.autoRefreshLevel == 0) {
            if (!this.fieldConfig.isForeignAutoRefresh()) {
                return createForeignShell(connectionSource, obj, objectCache);
            }
            levelCounters.autoRefreshLevelMax = this.fieldConfig.getMaxForeignAutoRefreshLevel();
        }
        if (levelCounters.autoRefreshLevel >= levelCounters.autoRefreshLevelMax) {
            return createForeignShell(connectionSource, obj, objectCache);
        }
        if (this.mappedQueryForForeignField == null) {
            Dao<?, ?> dao = this.foreignDao;
            this.mappedQueryForForeignField = MappedQueryForFieldEq.build(dao, dao.getTableInfo(), this.foreignIdField);
        }
        levelCounters.autoRefreshLevel++;
        try {
            DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableName);
            try {
                Object objExecute = this.mappedQueryForForeignField.execute(readOnlyConnection, obj, objectCache);
                int i = levelCounters.autoRefreshLevel - 1;
                levelCounters.autoRefreshLevel = i;
                if (i <= 0) {
                    threadLocal.remove();
                }
                return objExecute;
            } finally {
                connectionSource.releaseConnection(readOnlyConnection);
            }
        } catch (Throwable th) {
            int i2 = levelCounters.autoRefreshLevel - 1;
            levelCounters.autoRefreshLevel = i2;
            if (i2 <= 0) {
                threadLevelCounters.remove();
            }
            throw th;
        }
    }

    private <FT, FID> FT createForeignShell(ConnectionSource connectionSource, Object obj, ObjectCache objectCache) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        FT ft = (FT) this.foreignDao.createObjectInstance();
        this.foreignIdField.assignField(connectionSource, ft, obj, false, objectCache);
        return ft;
    }

    private <FT, FID> LazyForeignCollection<FT, FID> createLazyForeignCollection(Dao<FT, FID> dao, Object obj, Object obj2, FieldType fieldType, String str, boolean z) {
        return hasStreamClass ? new StreamableLazyForeignCollection(dao, obj, obj2, fieldType, str, z) : new LazyForeignCollection<>(dao, obj, obj2, fieldType, str, z);
    }

    private FieldType findForeignFieldType(Class<?> cls, Class<?> cls2, Dao<?, ?> dao) throws SQLException {
        String foreignCollectionForeignFieldName = this.fieldConfig.getForeignCollectionForeignFieldName();
        for (FieldType fieldType : dao.getTableInfo().getFieldTypes()) {
            if (fieldType.getType() == cls2 && (foreignCollectionForeignFieldName == null || fieldType.getField().getName().equals(foreignCollectionForeignFieldName))) {
                return fieldType;
            }
        }
        StringBuilder sb = new StringBuilder("Foreign collection class ");
        sb.append(cls.getName());
        sb.append(" for field '");
        sb.append(this.field.getName());
        sb.append("' column-name does not contain a foreign field");
        if (foreignCollectionForeignFieldName != null) {
            sb.append(" named '");
            sb.append(foreignCollectionForeignFieldName);
            sb.append('\'');
        }
        sb.append(" of class ");
        sb.append(cls2.getName());
        throw new SQLException(sb.toString());
    }

    private boolean isFieldValueDefault(Object obj) {
        if (obj == null) {
            return true;
        }
        return obj.equals(getJavaDefaultValueDefault());
    }

    public void assignField(ConnectionSource connectionSource, Object obj, Object obj2, boolean z, ObjectCache objectCache) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Logger logger2 = logger;
        if (logger2.isLevelEnabled(Level.TRACE)) {
            logger2.trace("assiging from data {}, val {}: {}", obj == null ? "null" : obj.getClass(), obj2 != null ? obj2.getClass() : "null", obj2);
        }
        if (this.foreignRefField != null && obj2 != null) {
            Object objExtractJavaFieldValue = extractJavaFieldValue(obj);
            if (objExtractJavaFieldValue != null && objExtractJavaFieldValue.equals(obj2)) {
                return;
            }
            ObjectCache objectCache2 = this.foreignDao.getObjectCache();
            Object obj3 = objectCache2 == null ? null : objectCache2.get(getType(), obj2);
            if (obj3 != null) {
                obj2 = obj3;
            } else if (!z) {
                obj2 = createForeignObject(connectionSource, obj2, objectCache);
            }
        }
        Method method = this.fieldSetMethod;
        if (method != null) {
            try {
                method.invoke(obj, obj2);
                return;
            } catch (Exception e) {
                throw new SQLException("Could not call " + this.fieldSetMethod + " on object with '" + obj2 + "' for " + this, e);
            }
        }
        try {
            this.field.set(obj, obj2);
        } catch (IllegalAccessException e2) {
            throw new SQLException("Could not assign object '" + obj2 + "' of type " + obj2.getClass() + "' to field " + this, e2);
        } catch (IllegalArgumentException e3) {
            if (obj2 == null) {
                throw new SQLException("Could not assign object '" + obj2 + "' to field " + this, e3);
            }
            throw new SQLException("Could not assign object '" + obj2 + "' of type " + obj2.getClass() + " to field " + this, e3);
        }
    }

    public Object assignIdValue(ConnectionSource connectionSource, Object obj, Number number, ObjectCache objectCache) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Object objConvertIdNumber = this.dataPersister.convertIdNumber(number);
        if (objConvertIdNumber != null) {
            assignField(connectionSource, obj, objConvertIdNumber, false, objectCache);
            return objConvertIdNumber;
        }
        throw new SQLException("Invalid class " + this.dataPersister + " for sequence-id " + this);
    }

    public <FT, FID> BaseForeignCollection<FT, FID> buildForeignCollection(Object obj, FID fid) throws SQLException {
        if (this.foreignFieldType == null) {
            return null;
        }
        Dao<?, ?> dao = this.foreignDao;
        if (!this.fieldConfig.isForeignCollectionEager()) {
            return createLazyForeignCollection(dao, obj, fid, this.foreignFieldType, this.fieldConfig.getForeignCollectionOrderColumnName(), this.fieldConfig.isForeignCollectionOrderAscending());
        }
        ThreadLocal<LevelCounters> threadLocal = threadLevelCounters;
        LevelCounters levelCounters = threadLocal.get();
        if (levelCounters == null) {
            if (this.fieldConfig.getForeignCollectionMaxEagerLevel() == 0) {
                return createLazyForeignCollection(dao, obj, fid, this.foreignFieldType, this.fieldConfig.getForeignCollectionOrderColumnName(), this.fieldConfig.isForeignCollectionOrderAscending());
            }
            levelCounters = new LevelCounters();
            threadLocal.set(levelCounters);
        }
        if (levelCounters.foreignCollectionLevel == 0) {
            levelCounters.foreignCollectionLevelMax = this.fieldConfig.getForeignCollectionMaxEagerLevel();
        }
        int i = levelCounters.foreignCollectionLevel;
        if (i >= levelCounters.foreignCollectionLevelMax) {
            return createLazyForeignCollection(dao, obj, fid, this.foreignFieldType, this.fieldConfig.getForeignCollectionOrderColumnName(), this.fieldConfig.isForeignCollectionOrderAscending());
        }
        levelCounters.foreignCollectionLevel = i + 1;
        try {
            return new EagerForeignCollection(dao, obj, fid, this.foreignFieldType, this.fieldConfig.getForeignCollectionOrderColumnName(), this.fieldConfig.isForeignCollectionOrderAscending());
        } finally {
            levelCounters.foreignCollectionLevel--;
        }
    }

    public <FT, FID> void configDaoInformation(ConnectionSource connectionSource, Class<?> cls) throws SQLException {
        Dao<?, ?> daoCreateDao;
        TableInfo<?, ?> tableInfo;
        FieldType idField;
        FieldType fieldTypeByColumnName;
        FieldType fieldTypeFindForeignFieldType;
        Class<?> type = this.field.getType();
        DatabaseType databaseType = connectionSource.getDatabaseType();
        String foreignColumnName = this.fieldConfig.getForeignColumnName();
        MappedQueryForFieldEq<?, ?> mappedQueryForFieldEqBuild = null;
        if (this.fieldConfig.isForeignAutoRefresh() || foreignColumnName != null) {
            DatabaseTableConfig<?> foreignTableConfig = this.fieldConfig.getForeignTableConfig();
            if (foreignTableConfig == null) {
                daoCreateDao = DaoManager.createDao(connectionSource, type);
                tableInfo = daoCreateDao.getTableInfo();
            } else {
                foreignTableConfig.extractFieldTypes(databaseType);
                daoCreateDao = DaoManager.createDao(connectionSource, foreignTableConfig);
                tableInfo = daoCreateDao.getTableInfo();
            }
            idField = tableInfo.getIdField();
            if (idField == null) {
                throw new IllegalArgumentException("Foreign field " + type + " does not have id field");
            }
            if (foreignColumnName == null) {
                fieldTypeByColumnName = idField;
            } else {
                fieldTypeByColumnName = tableInfo.getFieldTypeByColumnName(foreignColumnName);
                if (fieldTypeByColumnName == null) {
                    throw new IllegalArgumentException("Foreign field " + type + " does not have field named '" + foreignColumnName + "'");
                }
            }
            mappedQueryForFieldEqBuild = MappedQueryForFieldEq.build(daoCreateDao, tableInfo, fieldTypeByColumnName);
            fieldTypeFindForeignFieldType = null;
        } else if (this.fieldConfig.isForeign()) {
            DataPersister dataPersister = this.dataPersister;
            if (dataPersister != null && dataPersister.isPrimitive()) {
                throw new IllegalArgumentException("Field " + this + " is a primitive class " + type + " but marked as foreign");
            }
            DatabaseTableConfig<?> foreignTableConfig2 = this.fieldConfig.getForeignTableConfig();
            if (foreignTableConfig2 != null) {
                foreignTableConfig2.extractFieldTypes(databaseType);
                daoCreateDao = DaoManager.createDao(connectionSource, foreignTableConfig2);
            } else {
                daoCreateDao = DaoManager.createDao(connectionSource, type);
            }
            FieldType idField2 = daoCreateDao.getTableInfo().getIdField();
            if (idField2 == null) {
                throw new IllegalArgumentException("Foreign field " + type + " does not have id field");
            }
            if (isForeignAutoCreate() && !idField2.isGeneratedId()) {
                throw new IllegalArgumentException("Field " + this.field.getName() + ", if foreignAutoCreate = true then class " + type.getSimpleName() + " must have id field with generatedId = true");
            }
            idField = idField2;
            fieldTypeByColumnName = idField;
            fieldTypeFindForeignFieldType = null;
        } else {
            if (!this.fieldConfig.isForeignCollection()) {
                daoCreateDao = null;
                fieldTypeFindForeignFieldType = null;
                idField = null;
            } else {
                if (type != Collection.class && !ForeignCollection.class.isAssignableFrom(type)) {
                    throw new SQLException("Field class for '" + this.field.getName() + "' must be of class ForeignCollection or Collection.");
                }
                Type genericType = this.field.getGenericType();
                if (!(genericType instanceof ParameterizedType)) {
                    throw new SQLException("Field class for '" + this.field.getName() + "' must be a parameterized Collection.");
                }
                Type[] actualTypeArguments = ((ParameterizedType) genericType).getActualTypeArguments();
                if (actualTypeArguments.length == 0) {
                    throw new SQLException("Field class for '" + this.field.getName() + "' must be a parameterized Collection with at least 1 type.");
                }
                if (actualTypeArguments[0] instanceof TypeVariable) {
                    actualTypeArguments = ((ParameterizedType) cls.getGenericSuperclass()).getActualTypeArguments();
                }
                Type type2 = actualTypeArguments[0];
                if (!(type2 instanceof Class)) {
                    throw new SQLException("Field class for '" + this.field.getName() + "' must be a parameterized Collection whose generic argument is an entity class not: " + actualTypeArguments[0]);
                }
                Class<?> cls2 = (Class) type2;
                DatabaseTableConfig<?> foreignTableConfig3 = this.fieldConfig.getForeignTableConfig();
                daoCreateDao = foreignTableConfig3 == null ? DaoManager.createDao(connectionSource, cls2) : DaoManager.createDao(connectionSource, foreignTableConfig3);
                fieldTypeFindForeignFieldType = findForeignFieldType(cls2, cls, daoCreateDao);
                idField = null;
            }
            fieldTypeByColumnName = idField;
        }
        this.mappedQueryForForeignField = mappedQueryForFieldEqBuild;
        this.foreignFieldType = fieldTypeFindForeignFieldType;
        this.foreignDao = daoCreateDao;
        this.foreignIdField = idField;
        this.foreignRefField = fieldTypeByColumnName;
        if (fieldTypeByColumnName != null) {
            assignDataType(databaseType, fieldTypeByColumnName.getDataPersister());
        }
    }

    public Object convertJavaFieldToSqlArgValue(Object obj) throws SQLException {
        if (obj == null) {
            return null;
        }
        return this.fieldConverter.javaToSqlArg(this, obj);
    }

    public Object convertStringToJavaField(String str, int i) throws SQLException {
        if (str == null) {
            return null;
        }
        return this.fieldConverter.resultStringToJava(this, str, i);
    }

    public <T> int createWithForeignDao(T t) throws SQLException {
        return this.foreignDao.create((Dao<?, ?>) t);
    }

    public boolean equals(Object obj) {
        if (obj != null && obj.getClass() == getClass()) {
            FieldType fieldType = (FieldType) obj;
            if (this.field.equals(fieldType.field)) {
                Class<?> cls = this.parentClass;
                Class<?> cls2 = fieldType.parentClass;
                if (cls == null) {
                    if (cls2 == null) {
                        return true;
                    }
                } else if (cls.equals(cls2)) {
                    return true;
                }
            }
        }
        return false;
    }

    public Object extractJavaFieldToSqlArgValue(Object obj) throws SQLException {
        return convertJavaFieldToSqlArgValue(extractJavaFieldValue(obj));
    }

    public Object extractJavaFieldValue(Object obj) throws SQLException {
        Object objExtractRawJavaFieldValue = extractRawJavaFieldValue(obj);
        FieldType fieldType = this.foreignRefField;
        return (fieldType == null || objExtractRawJavaFieldValue == null) ? objExtractRawJavaFieldValue : fieldType.extractRawJavaFieldValue(objExtractRawJavaFieldValue);
    }

    public <FV> FV extractRawJavaFieldValue(Object obj) throws SQLException {
        Method method = this.fieldGetMethod;
        if (method == null) {
            try {
                return (FV) this.field.get(obj);
            } catch (Exception e) {
                throw new SQLException("Could not get field value for " + this, e);
            }
        }
        try {
            return (FV) method.invoke(obj, null);
        } catch (Exception e2) {
            throw new SQLException("Could not call " + this.fieldGetMethod + " for " + this, e2);
        }
    }

    public Object generateId() {
        return this.dataPersister.generateId();
    }

    public String getColumnDefinition() {
        String fullColumnDefinition = this.fieldConfig.getFullColumnDefinition();
        return fullColumnDefinition == null ? this.fieldConfig.getColumnDefinition() : fullColumnDefinition;
    }

    public String getColumnName() {
        return this.columnName;
    }

    public DataPersister getDataPersister() {
        return this.dataPersister;
    }

    public Object getDataTypeConfigObj() {
        return this.dataTypeConfigObj;
    }

    public Object getDefaultValue() {
        return this.defaultValue;
    }

    public Field getField() {
        return this.field;
    }

    public String getFieldName() {
        return this.field.getName();
    }

    public <FV> FV getFieldValueIfNotDefault(Object obj) throws SQLException {
        FV fv = (FV) extractJavaFieldValue(obj);
        if (isFieldValueDefault(fv)) {
            return null;
        }
        return fv;
    }

    public FieldType getForeignIdField() {
        return this.foreignIdField;
    }

    public FieldType getForeignRefField() {
        return this.foreignRefField;
    }

    public String getFormat() {
        return this.fieldConfig.getFormat();
    }

    public String getGeneratedIdSequence() {
        return this.generatedIdSequence;
    }

    public Type getGenericType() {
        return this.field.getGenericType();
    }

    public String getIndexName() {
        return this.fieldConfig.getIndexName(this.tableName);
    }

    public Object getJavaDefaultValueDefault() {
        if (this.field.getType() == Boolean.TYPE) {
            return Boolean.valueOf(DEFAULT_VALUE_BOOLEAN);
        }
        if (this.field.getType() == Byte.TYPE || this.field.getType() == Byte.class) {
            return Byte.valueOf(DEFAULT_VALUE_BYTE);
        }
        if (this.field.getType() == Character.TYPE || this.field.getType() == Character.class) {
            return Character.valueOf(DEFAULT_VALUE_CHAR);
        }
        if (this.field.getType() == Short.TYPE || this.field.getType() == Short.class) {
            return Short.valueOf(DEFAULT_VALUE_SHORT);
        }
        if (this.field.getType() == Integer.TYPE || this.field.getType() == Integer.class) {
            return Integer.valueOf(DEFAULT_VALUE_INT);
        }
        if (this.field.getType() == Long.TYPE || this.field.getType() == Long.class) {
            return Long.valueOf(DEFAULT_VALUE_LONG);
        }
        if (this.field.getType() == Float.TYPE || this.field.getType() == Float.class) {
            return Float.valueOf(DEFAULT_VALUE_FLOAT);
        }
        if (this.field.getType() == Double.TYPE || this.field.getType() == Double.class) {
            return Double.valueOf(DEFAULT_VALUE_DOUBLE);
        }
        return null;
    }

    public SqlType getSqlType() {
        return this.fieldConverter.getSqlType();
    }

    public String getTableName() {
        return this.tableName;
    }

    public Class<?> getType() {
        return this.field.getType();
    }

    public String getUniqueIndexName() {
        return this.fieldConfig.getUniqueIndexName(this.tableName);
    }

    public Enum<?> getUnknownEnumVal() {
        return this.fieldConfig.getUnknownEnumValue();
    }

    public int getWidth() {
        return this.fieldConfig.getWidth();
    }

    public int hashCode() {
        return this.field.hashCode();
    }

    public boolean isAllowGeneratedIdInsert() {
        return this.fieldConfig.isAllowGeneratedIdInsert();
    }

    public boolean isArgumentHolderRequired() {
        return this.dataPersister.isArgumentHolderRequired();
    }

    public boolean isCanBeNull() {
        return this.fieldConfig.isCanBeNull();
    }

    public boolean isComparable() throws SQLException {
        if (this.fieldConfig.isForeignCollection()) {
            return false;
        }
        DataPersister dataPersister = this.dataPersister;
        if (dataPersister != null) {
            return dataPersister.isComparable();
        }
        throw new SQLException("Internal error.  Data-persister is not configured for field.  Please post _full_ exception with associated data objects to mailing list: " + this);
    }

    public boolean isEscapedDefaultValue() {
        return this.dataPersister.isEscapedDefaultValue();
    }

    public boolean isEscapedValue() {
        return this.dataPersister.isEscapedValue();
    }

    public boolean isForeign() {
        return this.fieldConfig.isForeign();
    }

    public boolean isForeignAutoCreate() {
        return this.fieldConfig.isForeignAutoCreate();
    }

    public boolean isForeignCollection() {
        return this.fieldConfig.isForeignCollection();
    }

    public boolean isGeneratedId() {
        return this.isGeneratedId;
    }

    public boolean isGeneratedIdSequence() {
        return this.generatedIdSequence != null;
    }

    public boolean isId() {
        return this.isId;
    }

    public boolean isObjectsFieldValueDefault(Object obj) throws SQLException {
        return isFieldValueDefault(extractJavaFieldValue(obj));
    }

    public boolean isReadOnly() {
        return this.fieldConfig.isReadOnly();
    }

    public boolean isSelfGeneratedId() {
        return this.dataPersister.isSelfGeneratedId();
    }

    public boolean isUnique() {
        return this.fieldConfig.isUnique();
    }

    public boolean isUniqueCombo() {
        return this.fieldConfig.isUniqueCombo();
    }

    public boolean isVersion() {
        return this.fieldConfig.isVersion();
    }

    public Object moveToNextValue(Object obj) throws SQLException {
        DataPersister dataPersister = this.dataPersister;
        if (dataPersister == null) {
            return null;
        }
        return dataPersister.moveToNextValue(obj);
    }

    public <T> T resultToJava(DatabaseResults databaseResults, Map<String, Integer> map) throws SQLException {
        Integer numValueOf = map.get(this.columnName);
        if (numValueOf == null) {
            numValueOf = Integer.valueOf(databaseResults.findColumn(this.columnName));
            map.put(this.columnName, numValueOf);
        }
        T t = (T) this.fieldConverter.resultToJava(this, databaseResults, numValueOf.intValue());
        if (this.fieldConfig.isForeign()) {
            if (databaseResults.wasNull(numValueOf.intValue())) {
                return null;
            }
        } else if (this.dataPersister.isPrimitive()) {
            if (this.fieldConfig.isThrowIfNull() && databaseResults.wasNull(numValueOf.intValue())) {
                throw new SQLException("Results value for primitive field '" + this.field.getName() + "' was an invalid null value");
            }
        } else if (!this.fieldConverter.isStreamType() && databaseResults.wasNull(numValueOf.intValue())) {
            return null;
        }
        return t;
    }

    public String toString() {
        return getClass().getSimpleName() + ":name=" + this.field.getName() + ",class=" + this.field.getDeclaringClass().getSimpleName();
    }
}
