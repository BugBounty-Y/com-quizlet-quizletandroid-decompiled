package com.j256.ormlite.dao;

import androidx.compose.ui.node.B;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.DatabaseTable;
import com.j256.ormlite.table.DatabaseTableConfig;
import java.lang.reflect.Constructor;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public class DaoManager {
    private static Map<ClassConnectionSource, Dao<?, ?>> classMap;
    private static Map<Class<?>, DatabaseTableConfig<?>> configMap;
    private static Logger logger = LoggerFactory.getLogger((Class<?>) DaoManager.class);
    private static Map<TableConfigConnectionSource, Dao<?, ?>> tableConfigMap;

    public static class ClassConnectionSource {
        Class<?> clazz;
        ConnectionSource connectionSource;

        public ClassConnectionSource(ConnectionSource connectionSource, Class<?> cls) {
            this.connectionSource = connectionSource;
            this.clazz = cls;
        }

        public boolean equals(Object obj) {
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            ClassConnectionSource classConnectionSource = (ClassConnectionSource) obj;
            return this.clazz.equals(classConnectionSource.clazz) && this.connectionSource.equals(classConnectionSource.connectionSource);
        }

        public int hashCode() {
            return this.connectionSource.hashCode() + ((this.clazz.hashCode() + 31) * 31);
        }
    }

    public static class TableConfigConnectionSource {
        ConnectionSource connectionSource;
        DatabaseTableConfig<?> tableConfig;

        public TableConfigConnectionSource(ConnectionSource connectionSource, DatabaseTableConfig<?> databaseTableConfig) {
            this.connectionSource = connectionSource;
            this.tableConfig = databaseTableConfig;
        }

        public boolean equals(Object obj) {
            if (obj == null || getClass() != obj.getClass()) {
                return false;
            }
            TableConfigConnectionSource tableConfigConnectionSource = (TableConfigConnectionSource) obj;
            return this.tableConfig.equals(tableConfigConnectionSource.tableConfig) && this.connectionSource.equals(tableConfigConnectionSource.connectionSource);
        }

        public int hashCode() {
            return this.connectionSource.hashCode() + ((this.tableConfig.hashCode() + 31) * 31);
        }
    }

    public static synchronized void addCachedDatabaseConfigs(Collection<DatabaseTableConfig<?>> collection) {
        try {
            HashMap map = configMap == null ? new HashMap() : new HashMap(configMap);
            for (DatabaseTableConfig<?> databaseTableConfig : collection) {
                map.put(databaseTableConfig.getDataClass(), databaseTableConfig);
                logger.info("Loaded configuration for {}", databaseTableConfig.getDataClass());
            }
            configMap = map;
        } catch (Throwable th) {
            throw th;
        }
    }

    private static void addDaoToClassMap(ClassConnectionSource classConnectionSource, Dao<?, ?> dao) {
        if (classMap == null) {
            classMap = new HashMap();
        }
        classMap.put(classConnectionSource, dao);
    }

    private static void addDaoToTableMap(TableConfigConnectionSource tableConfigConnectionSource, Dao<?, ?> dao) {
        if (tableConfigMap == null) {
            tableConfigMap = new HashMap();
        }
        tableConfigMap.put(tableConfigConnectionSource, dao);
    }

    public static synchronized void clearCache() {
        try {
            Map<Class<?>, DatabaseTableConfig<?>> map = configMap;
            if (map != null) {
                map.clear();
                configMap = null;
            }
            clearDaoCache();
        } catch (Throwable th) {
            throw th;
        }
    }

    public static synchronized void clearDaoCache() {
        try {
            Map<ClassConnectionSource, Dao<?, ?>> map = classMap;
            if (map != null) {
                map.clear();
                classMap = null;
            }
            Map<TableConfigConnectionSource, Dao<?, ?>> map2 = tableConfigMap;
            if (map2 != null) {
                map2.clear();
                tableConfigMap = null;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public static synchronized <D extends Dao<T, ?>, T> D createDao(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        D d;
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        D d2 = (D) lookupDao(new ClassConnectionSource(connectionSource, cls));
        if (d2 != null) {
            return d2;
        }
        D d3 = (D) createDaoFromConfig(connectionSource, cls);
        if (d3 != null) {
            return d3;
        }
        DatabaseTable databaseTable = (DatabaseTable) cls.getAnnotation(DatabaseTable.class);
        if (databaseTable == null || databaseTable.daoClass() == Void.class || databaseTable.daoClass() == BaseDaoImpl.class) {
            DatabaseTableConfig<T> databaseTableConfigExtractDatabaseTableConfig = connectionSource.getDatabaseType().extractDatabaseTableConfig(connectionSource, cls);
            d = (D) (databaseTableConfigExtractDatabaseTableConfig == null ? BaseDaoImpl.createDao(connectionSource, cls) : BaseDaoImpl.createDao(connectionSource, databaseTableConfigExtractDatabaseTableConfig));
            logger.debug("created dao for class {} with reflection", cls);
        } else {
            Class<?> clsDaoClass = databaseTable.daoClass();
            Object[] objArr = {connectionSource, cls};
            Constructor<?> constructorFindConstructor = findConstructor(clsDaoClass, objArr);
            if (constructorFindConstructor == null && (constructorFindConstructor = findConstructor(clsDaoClass, (objArr = new Object[]{connectionSource}))) == null) {
                throw new SQLException("Could not find public constructor with ConnectionSource and optional Class parameters " + clsDaoClass + ".  Missing static on class?");
            }
            try {
                d = (D) constructorFindConstructor.newInstance(objArr);
                logger.debug("created dao for class {} from constructor", cls);
            } catch (Exception e) {
                throw new SQLException("Could not call the constructor in class " + clsDaoClass, e);
            }
        }
        registerDao(connectionSource, d);
        return d;
    }

    private static <D, T> D createDaoFromConfig(ConnectionSource connectionSource, Class<T> cls) throws SQLException {
        DatabaseTableConfig<?> databaseTableConfig;
        Map<Class<?>, DatabaseTableConfig<?>> map = configMap;
        if (map == null || (databaseTableConfig = map.get(cls)) == null) {
            return null;
        }
        return (D) doCreateDao(connectionSource, databaseTableConfig);
    }

    private static <D extends Dao<T, ?>, T> D doCreateDao(ConnectionSource connectionSource, DatabaseTableConfig<T> databaseTableConfig) throws SQLException, SecurityException {
        D d;
        TableConfigConnectionSource tableConfigConnectionSource = new TableConfigConnectionSource(connectionSource, databaseTableConfig);
        D d2 = (D) lookupDao(tableConfigConnectionSource);
        if (d2 != null) {
            return d2;
        }
        Class<T> dataClass = databaseTableConfig.getDataClass();
        ClassConnectionSource classConnectionSource = new ClassConnectionSource(connectionSource, dataClass);
        D d3 = (D) lookupDao(classConnectionSource);
        if (d3 != null) {
            addDaoToTableMap(tableConfigConnectionSource, d3);
            return d3;
        }
        DatabaseTable databaseTable = (DatabaseTable) databaseTableConfig.getDataClass().getAnnotation(DatabaseTable.class);
        if (databaseTable == null || databaseTable.daoClass() == Void.class || databaseTable.daoClass() == BaseDaoImpl.class) {
            d = (D) BaseDaoImpl.createDao(connectionSource, databaseTableConfig);
        } else {
            Class<?> clsDaoClass = databaseTable.daoClass();
            Object[] objArr = {connectionSource, databaseTableConfig};
            Constructor<?> constructorFindConstructor = findConstructor(clsDaoClass, objArr);
            if (constructorFindConstructor == null) {
                throw new SQLException(B.d(clsDaoClass, "Could not find public constructor with ConnectionSource, DatabaseTableConfig parameters in class "));
            }
            try {
                d = (D) constructorFindConstructor.newInstance(objArr);
            } catch (Exception e) {
                throw new SQLException(B.d(clsDaoClass, "Could not call the constructor in class "), e);
            }
        }
        addDaoToTableMap(tableConfigConnectionSource, d);
        logger.debug("created dao for class {} from table config", dataClass);
        if (lookupDao(classConnectionSource) == null) {
            addDaoToClassMap(classConnectionSource, d);
        }
        return d;
    }

    private static Constructor<?> findConstructor(Class<?> cls, Object[] objArr) throws SecurityException {
        for (Constructor<?> constructor : cls.getConstructors()) {
            Class<?>[] parameterTypes = constructor.getParameterTypes();
            if (parameterTypes.length == objArr.length) {
                for (int i = 0; i < parameterTypes.length; i++) {
                    if (!parameterTypes[i].isAssignableFrom(objArr[i].getClass())) {
                        break;
                    }
                }
                return constructor;
            }
        }
        return null;
    }

    public static synchronized <D extends Dao<T, ?>, T> D lookupDao(ConnectionSource connectionSource, Class<T> cls) {
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        return (D) lookupDao(new ClassConnectionSource(connectionSource, cls));
    }

    public static synchronized void registerDao(ConnectionSource connectionSource, Dao<?, ?> dao) {
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        addDaoToClassMap(new ClassConnectionSource(connectionSource, dao.getDataClass()), dao);
    }

    public static synchronized void registerDaoWithTableConfig(ConnectionSource connectionSource, Dao<?, ?> dao) {
        DatabaseTableConfig tableConfig;
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        if (!(dao instanceof BaseDaoImpl) || (tableConfig = ((BaseDaoImpl) dao).getTableConfig()) == null) {
            addDaoToClassMap(new ClassConnectionSource(connectionSource, dao.getDataClass()), dao);
        } else {
            addDaoToTableMap(new TableConfigConnectionSource(connectionSource, tableConfig), dao);
        }
    }

    private static void removeDaoToClassMap(ClassConnectionSource classConnectionSource) {
        Map<ClassConnectionSource, Dao<?, ?>> map = classMap;
        if (map != null) {
            map.remove(classConnectionSource);
        }
    }

    private static void removeDaosFromConnectionClassMap(ConnectionSource connectionSource) {
        Map<ClassConnectionSource, Dao<?, ?>> map = classMap;
        if (map != null) {
            Iterator<ClassConnectionSource> it2 = map.keySet().iterator();
            while (it2.hasNext()) {
                if (it2.next().connectionSource == connectionSource) {
                    it2.remove();
                }
            }
        }
    }

    public static synchronized void unregisterDao(ConnectionSource connectionSource, Dao<?, ?> dao) {
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        removeDaoToClassMap(new ClassConnectionSource(connectionSource, dao.getDataClass()));
    }

    public static synchronized void unregisterDaos(ConnectionSource connectionSource) {
        if (connectionSource == null) {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        removeDaosFromConnectionClassMap(connectionSource);
    }

    public static synchronized <D extends Dao<T, ?>, T> D lookupDao(ConnectionSource connectionSource, DatabaseTableConfig<T> databaseTableConfig) {
        if (connectionSource != null) {
            D d = (D) lookupDao(new TableConfigConnectionSource(connectionSource, databaseTableConfig));
            if (d == null) {
                return null;
            }
            return d;
        }
        throw new IllegalArgumentException("connectionSource argument cannot be null");
    }

    private static <T> Dao<?, ?> lookupDao(ClassConnectionSource classConnectionSource) {
        if (classMap == null) {
            classMap = new HashMap();
        }
        Dao<?, ?> dao = classMap.get(classConnectionSource);
        if (dao == null) {
            return null;
        }
        return dao;
    }

    private static <T> Dao<?, ?> lookupDao(TableConfigConnectionSource tableConfigConnectionSource) {
        if (tableConfigMap == null) {
            tableConfigMap = new HashMap();
        }
        Dao<?, ?> dao = tableConfigMap.get(tableConfigConnectionSource);
        if (dao == null) {
            return null;
        }
        return dao;
    }

    public static synchronized <D extends Dao<T, ?>, T> D createDao(ConnectionSource connectionSource, DatabaseTableConfig<T> databaseTableConfig) throws SQLException {
        if (connectionSource != null) {
        } else {
            throw new IllegalArgumentException("connectionSource argument cannot be null");
        }
        return (D) doCreateDao(connectionSource, databaseTableConfig);
    }
}
