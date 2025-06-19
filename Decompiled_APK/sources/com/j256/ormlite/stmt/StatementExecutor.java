package com.j256.ormlite.stmt;

import androidx.compose.ui.node.B;
import com.j256.ormlite.dao.BaseDaoImpl;
import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DatabaseResultsMapper;
import com.j256.ormlite.dao.GenericRawResults;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.dao.RawRowMapper;
import com.j256.ormlite.dao.RawRowObjectMapper;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.misc.IOUtils;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.stmt.mapped.MappedCreate;
import com.j256.ormlite.stmt.mapped.MappedDelete;
import com.j256.ormlite.stmt.mapped.MappedDeleteCollection;
import com.j256.ormlite.stmt.mapped.MappedQueryForFieldEq;
import com.j256.ormlite.stmt.mapped.MappedRefresh;
import com.j256.ormlite.stmt.mapped.MappedUpdate;
import com.j256.ormlite.stmt.mapped.MappedUpdateId;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.DatabaseResults;
import com.j256.ormlite.table.TableInfo;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public class StatementExecutor<T, ID> implements GenericRowMapper<String[]> {
    private static Logger logger = LoggerFactory.getLogger((Class<?>) StatementExecutor.class);
    private static final FieldType[] noFieldTypes = new FieldType[0];
    private String countStarQuery;
    private final Dao<T, ID> dao;
    private final DatabaseType databaseType;
    private FieldType[] ifExistsFieldTypes;
    private String ifExistsQuery;
    private final ThreadLocal<Boolean> localIsInBatchMode = new ThreadLocal<Boolean>() { // from class: com.j256.ormlite.stmt.StatementExecutor.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.lang.ThreadLocal
        public Boolean initialValue() {
            return Boolean.FALSE;
        }
    };
    private MappedDelete<T, ID> mappedDelete;
    private MappedCreate<T, ID> mappedInsert;
    private MappedQueryForFieldEq<T, ID> mappedQueryForId;
    private MappedRefresh<T, ID> mappedRefresh;
    private MappedUpdate<T, ID> mappedUpdate;
    private MappedUpdateId<T, ID> mappedUpdateId;
    private PreparedQuery<T> preparedQueryForAll;
    private RawRowMapper<T> rawRowMapper;
    private final TableInfo<T, ID> tableInfo;

    public static class ObjectArrayRowMapper implements GenericRowMapper<Object[]> {
        private final DataType[] columnTypes;

        public ObjectArrayRowMapper(DataType[] dataTypeArr) {
            this.columnTypes = dataTypeArr;
        }

        @Override // com.j256.ormlite.stmt.GenericRowMapper
        public Object[] mapRow(DatabaseResults databaseResults) throws SQLException {
            int columnCount = databaseResults.getColumnCount();
            Object[] objArr = new Object[columnCount];
            int i = 0;
            while (i < columnCount) {
                DataType[] dataTypeArr = this.columnTypes;
                objArr[i] = (i >= dataTypeArr.length ? DataType.STRING : dataTypeArr[i]).getDataPersister().resultToJava(null, databaseResults, i);
                i++;
            }
            return objArr;
        }
    }

    public static class UserDatabaseResultsMapper<UO> implements GenericRowMapper<UO> {
        public final DatabaseResultsMapper<UO> mapper;

        @Override // com.j256.ormlite.stmt.GenericRowMapper
        public UO mapRow(DatabaseResults databaseResults) throws SQLException {
            return this.mapper.mapRow(databaseResults);
        }

        private UserDatabaseResultsMapper(DatabaseResultsMapper<UO> databaseResultsMapper) {
            this.mapper = databaseResultsMapper;
        }
    }

    public static class UserRawRowMapper<UO> implements GenericRowMapper<UO> {
        private String[] columnNames;
        private final RawRowMapper<UO> mapper;
        private final GenericRowMapper<String[]> stringRowMapper;

        public UserRawRowMapper(RawRowMapper<UO> rawRowMapper, GenericRowMapper<String[]> genericRowMapper) {
            this.mapper = rawRowMapper;
            this.stringRowMapper = genericRowMapper;
        }

        private String[] getColumnNames(DatabaseResults databaseResults) throws SQLException {
            String[] strArr = this.columnNames;
            if (strArr != null) {
                return strArr;
            }
            String[] columnNames = databaseResults.getColumnNames();
            this.columnNames = columnNames;
            return columnNames;
        }

        @Override // com.j256.ormlite.stmt.GenericRowMapper
        public UO mapRow(DatabaseResults databaseResults) throws SQLException {
            return this.mapper.mapRow(getColumnNames(databaseResults), this.stringRowMapper.mapRow(databaseResults));
        }
    }

    public static class UserRawRowObjectMapper<UO> implements GenericRowMapper<UO> {
        private String[] columnNames;
        private final DataType[] columnTypes;
        private final RawRowObjectMapper<UO> mapper;

        public UserRawRowObjectMapper(RawRowObjectMapper<UO> rawRowObjectMapper, DataType[] dataTypeArr) {
            this.mapper = rawRowObjectMapper;
            this.columnTypes = dataTypeArr;
        }

        private String[] getColumnNames(DatabaseResults databaseResults) throws SQLException {
            String[] strArr = this.columnNames;
            if (strArr != null) {
                return strArr;
            }
            String[] columnNames = databaseResults.getColumnNames();
            this.columnNames = columnNames;
            return columnNames;
        }

        @Override // com.j256.ormlite.stmt.GenericRowMapper
        public UO mapRow(DatabaseResults databaseResults) throws SQLException {
            int columnCount = databaseResults.getColumnCount();
            Object[] objArr = new Object[columnCount];
            for (int i = 0; i < columnCount; i++) {
                DataType[] dataTypeArr = this.columnTypes;
                if (i >= dataTypeArr.length) {
                    objArr[i] = null;
                } else {
                    objArr[i] = dataTypeArr[i].getDataPersister().resultToJava(null, databaseResults, i);
                }
            }
            return this.mapper.mapRow(getColumnNames(databaseResults), this.columnTypes, objArr);
        }
    }

    public StatementExecutor(DatabaseType databaseType, TableInfo<T, ID> tableInfo, Dao<T, ID> dao) {
        this.databaseType = databaseType;
        this.tableInfo = tableInfo;
        this.dao = dao;
    }

    private void assignStatementArguments(CompiledStatement compiledStatement, String[] strArr) throws SQLException {
        for (int i = 0; i < strArr.length; i++) {
            compiledStatement.setObject(i, strArr[i], SqlType.STRING);
        }
    }

    private <CT> CT doCallBatchTasks(ConnectionSource connectionSource, Callable<CT> callable) throws SQLException {
        DatabaseConnection readWriteConnection = connectionSource.getReadWriteConnection(this.tableInfo.getTableName());
        try {
            this.localIsInBatchMode.set(Boolean.TRUE);
            return (CT) doCallBatchTasks(readWriteConnection, connectionSource.saveSpecialConnection(readWriteConnection), callable);
        } finally {
            connectionSource.clearSpecialConnection(readWriteConnection);
            connectionSource.releaseConnection(readWriteConnection);
            this.localIsInBatchMode.set(Boolean.FALSE);
            Dao<T, ID> dao = this.dao;
            if (dao != null) {
                dao.notifyChanges();
            }
        }
    }

    private void prepareQueryForAll() throws SQLException {
        if (this.preparedQueryForAll == null) {
            this.preparedQueryForAll = new QueryBuilder(this.databaseType, this.tableInfo, this.dao).prepare();
        }
    }

    public SelectIterator<T, ID> buildIterator(BaseDaoImpl<T, ID> baseDaoImpl, ConnectionSource connectionSource, int i, ObjectCache objectCache) throws SQLException {
        prepareQueryForAll();
        return buildIterator(baseDaoImpl, connectionSource, this.preparedQueryForAll, objectCache, i);
    }

    public <CT> CT callBatchTasks(ConnectionSource connectionSource, Callable<CT> callable) throws SQLException {
        CT ct;
        if (!connectionSource.isSingleConnection(this.tableInfo.getTableName())) {
            return (CT) doCallBatchTasks(connectionSource, callable);
        }
        synchronized (this) {
            ct = (CT) doCallBatchTasks(connectionSource, callable);
        }
        return ct;
    }

    public int create(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        if (this.mappedInsert == null) {
            this.mappedInsert = MappedCreate.build(this.dao, this.tableInfo);
        }
        int iInsert = this.mappedInsert.insert(this.databaseType, databaseConnection, t, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iInsert;
    }

    public int delete(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws SQLException {
        if (this.mappedDelete == null) {
            this.mappedDelete = MappedDelete.build(this.dao, this.tableInfo);
        }
        int iDelete = this.mappedDelete.delete(databaseConnection, t, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iDelete;
    }

    public int deleteById(DatabaseConnection databaseConnection, ID id, ObjectCache objectCache) throws SQLException {
        if (this.mappedDelete == null) {
            this.mappedDelete = MappedDelete.build(this.dao, this.tableInfo);
        }
        int iDeleteById = this.mappedDelete.deleteById(databaseConnection, id, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iDeleteById;
    }

    public int deleteIds(DatabaseConnection databaseConnection, Collection<ID> collection, ObjectCache objectCache) throws SQLException {
        int iDeleteIds = MappedDeleteCollection.deleteIds(this.dao, this.tableInfo, databaseConnection, collection, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iDeleteIds;
    }

    public int deleteObjects(DatabaseConnection databaseConnection, Collection<T> collection, ObjectCache objectCache) throws SQLException {
        int iDeleteObjects = MappedDeleteCollection.deleteObjects(this.dao, this.tableInfo, databaseConnection, collection, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iDeleteObjects;
    }

    public int executeRaw(DatabaseConnection databaseConnection, String str, String[] strArr) throws SQLException {
        logger.debug("running raw execute statement: {}", str);
        if (strArr.length > 0) {
            logger.trace("execute arguments: {}", (Object) strArr);
        }
        CompiledStatement compiledStatementCompileStatement = databaseConnection.compileStatement(str, StatementBuilder.StatementType.EXECUTE, noFieldTypes, -1, false);
        try {
            assignStatementArguments(compiledStatementCompileStatement, strArr);
            return compiledStatementCompileStatement.runExecute();
        } finally {
            IOUtils.closeThrowSqlException(compiledStatementCompileStatement, "compiled statement");
        }
    }

    public int executeRawNoArgs(DatabaseConnection databaseConnection, String str) throws SQLException {
        logger.debug("running raw execute statement: {}", str);
        return databaseConnection.executeStatement(str, -1);
    }

    public RawRowMapper<T> getRawRowMapper() {
        if (this.rawRowMapper == null) {
            this.rawRowMapper = new RawRowMapperImpl(this.dao);
        }
        return this.rawRowMapper;
    }

    public GenericRowMapper<T> getSelectStarRowMapper() throws SQLException {
        prepareQueryForAll();
        return this.preparedQueryForAll;
    }

    public boolean ifExists(DatabaseConnection databaseConnection, ID id) throws SQLException {
        if (this.ifExistsQuery == null) {
            QueryBuilder queryBuilder = new QueryBuilder(this.databaseType, this.tableInfo, this.dao);
            queryBuilder.selectRaw("COUNT(*)");
            queryBuilder.where().eq(this.tableInfo.getIdField().getColumnName(), new SelectArg());
            this.ifExistsQuery = queryBuilder.prepareStatementString();
            this.ifExistsFieldTypes = new FieldType[]{this.tableInfo.getIdField()};
        }
        long jQueryForLong = databaseConnection.queryForLong(this.ifExistsQuery, new Object[]{this.tableInfo.getIdField().convertJavaFieldToSqlArgValue(id)}, this.ifExistsFieldTypes);
        logger.debug("query of '{}' returned {}", this.ifExistsQuery, Long.valueOf(jQueryForLong));
        return jQueryForLong != 0;
    }

    public List<T> query(ConnectionSource connectionSource, PreparedStmt<T> preparedStmt, ObjectCache objectCache) throws Throwable {
        SelectIterator<T, ID> selectIteratorBuildIterator = buildIterator(null, connectionSource, preparedStmt, objectCache, -1);
        try {
            ArrayList arrayList = new ArrayList();
            while (selectIteratorBuildIterator.hasNextThrow()) {
                arrayList.add(selectIteratorBuildIterator.nextThrow());
            }
            logger.debug("query of '{}' with {} args returned {} results", preparedStmt, Integer.valueOf(preparedStmt.getNumArgs()), Integer.valueOf(arrayList.size()));
            IOUtils.closeThrowSqlException(selectIteratorBuildIterator, "iterator");
            return arrayList;
        } catch (Throwable th) {
            IOUtils.closeThrowSqlException(selectIteratorBuildIterator, "iterator");
            throw th;
        }
    }

    public List<T> queryForAll(ConnectionSource connectionSource, ObjectCache objectCache) throws SQLException {
        prepareQueryForAll();
        return query(connectionSource, this.preparedQueryForAll, objectCache);
    }

    public long queryForCountStar(DatabaseConnection databaseConnection) throws SQLException {
        if (this.countStarQuery == null) {
            StringBuilder sbL = B.l(64, "SELECT COUNT(*) FROM ");
            if (this.tableInfo.getSchemaName() != null && this.tableInfo.getSchemaName().length() > 0) {
                this.databaseType.appendEscapedEntityName(sbL, this.tableInfo.getSchemaName());
                sbL.append('.');
            }
            this.databaseType.appendEscapedEntityName(sbL, this.tableInfo.getTableName());
            this.countStarQuery = sbL.toString();
        }
        long jQueryForLong = databaseConnection.queryForLong(this.countStarQuery);
        logger.debug("query of '{}' returned {}", this.countStarQuery, Long.valueOf(jQueryForLong));
        return jQueryForLong;
    }

    public T queryForFirst(DatabaseConnection databaseConnection, PreparedStmt<T> preparedStmt, ObjectCache objectCache) throws Throwable {
        CompiledStatement compiledStatementCompile = preparedStmt.compile(databaseConnection, StatementBuilder.StatementType.SELECT);
        DatabaseResults databaseResults = null;
        try {
            compiledStatementCompile.setMaxRows(1);
            DatabaseResults databaseResultsRunQuery = compiledStatementCompile.runQuery(objectCache);
            try {
                if (!databaseResultsRunQuery.first()) {
                    logger.debug("query-for-first of '{}' with {} args returned 0 results", preparedStmt, Integer.valueOf(preparedStmt.getNumArgs()));
                    IOUtils.closeThrowSqlException(databaseResultsRunQuery, "results");
                    IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
                    return null;
                }
                logger.debug("query-for-first of '{}' with {} args returned at least 1 result", preparedStmt, Integer.valueOf(preparedStmt.getNumArgs()));
                T t = (T) preparedStmt.mapRow(databaseResultsRunQuery);
                IOUtils.closeThrowSqlException(databaseResultsRunQuery, "results");
                IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
                return t;
            } catch (Throwable th) {
                th = th;
                databaseResults = databaseResultsRunQuery;
                IOUtils.closeThrowSqlException(databaseResults, "results");
                IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public T queryForId(DatabaseConnection databaseConnection, ID id, ObjectCache objectCache) throws SQLException {
        if (this.mappedQueryForId == null) {
            this.mappedQueryForId = MappedQueryForFieldEq.build(this.dao, this.tableInfo, null);
        }
        return this.mappedQueryForId.execute(databaseConnection, id, objectCache);
    }

    public long queryForLong(DatabaseConnection databaseConnection, PreparedStmt<T> preparedStmt) throws SQLException {
        CompiledStatement compiledStatementCompile = preparedStmt.compile(databaseConnection, StatementBuilder.StatementType.SELECT_LONG);
        try {
            DatabaseResults databaseResultsRunQuery = compiledStatementCompile.runQuery(null);
            if (!databaseResultsRunQuery.first()) {
                throw new SQLException("No result found in queryForLong: " + preparedStmt);
            }
            long j = databaseResultsRunQuery.getLong(0);
            IOUtils.closeThrowSqlException(databaseResultsRunQuery, "results");
            IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
            return j;
        } catch (Throwable th) {
            IOUtils.closeThrowSqlException((AutoCloseable) null, "results");
            IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
            throw th;
        }
    }

    public GenericRawResults<String[]> queryRaw(ConnectionSource connectionSource, String str, String[] strArr, ObjectCache objectCache) throws Throwable {
        ConnectionSource connectionSource2;
        Throwable th;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        try {
            compiledStatementCompileStatement = readOnlyConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
            try {
                assignStatementArguments(compiledStatementCompileStatement, strArr);
                try {
                    connectionSource2 = connectionSource;
                } catch (Throwable th2) {
                    th = th2;
                    connectionSource2 = connectionSource;
                }
            } catch (Throwable th3) {
                th = th3;
                connectionSource2 = connectionSource;
            }
        } catch (Throwable th4) {
            connectionSource2 = connectionSource;
            th = th4;
        }
        try {
            RawResultsImpl rawResultsImpl = new RawResultsImpl(connectionSource2, readOnlyConnection, String[].class, compiledStatementCompileStatement, this, objectCache);
            IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
            return rawResultsImpl;
        } catch (Throwable th5) {
            th = th5;
            readOnlyConnection = readOnlyConnection;
            th = th;
            compiledStatement = compiledStatementCompileStatement;
            IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
            if (readOnlyConnection == null) {
                throw th;
            }
            connectionSource2.releaseConnection(readOnlyConnection);
            throw th;
        }
    }

    public int refresh(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws SQLException {
        if (this.mappedRefresh == null) {
            this.mappedRefresh = MappedRefresh.build(this.dao, this.tableInfo);
        }
        return this.mappedRefresh.executeRefresh(databaseConnection, t, objectCache);
    }

    public int update(DatabaseConnection databaseConnection, T t, ObjectCache objectCache) throws IllegalAccessException, SQLException, IllegalArgumentException, InvocationTargetException {
        if (this.mappedUpdate == null) {
            this.mappedUpdate = MappedUpdate.build(this.dao, this.tableInfo);
        }
        int iUpdate = this.mappedUpdate.update(databaseConnection, t, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iUpdate;
    }

    public int updateId(DatabaseConnection databaseConnection, T t, ID id, ObjectCache objectCache) throws IllegalAccessException, SQLException, IllegalArgumentException, InvocationTargetException {
        if (this.mappedUpdateId == null) {
            this.mappedUpdateId = MappedUpdateId.build(this.dao, this.tableInfo);
        }
        int iExecute = this.mappedUpdateId.execute(databaseConnection, t, id, objectCache);
        if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
            this.dao.notifyChanges();
        }
        return iExecute;
    }

    public int updateRaw(DatabaseConnection databaseConnection, String str, String[] strArr) throws SQLException {
        logger.debug("running raw update statement: {}", str);
        if (strArr.length > 0) {
            logger.trace("update arguments: {}", (Object) strArr);
        }
        CompiledStatement compiledStatementCompileStatement = databaseConnection.compileStatement(str, StatementBuilder.StatementType.UPDATE, noFieldTypes, -1, false);
        try {
            assignStatementArguments(compiledStatementCompileStatement, strArr);
            return compiledStatementCompileStatement.runUpdate();
        } finally {
            IOUtils.closeThrowSqlException(compiledStatementCompileStatement, "compiled statement");
        }
    }

    @Override // com.j256.ormlite.stmt.GenericRowMapper
    public String[] mapRow(DatabaseResults databaseResults) throws SQLException {
        int columnCount = databaseResults.getColumnCount();
        String[] strArr = new String[columnCount];
        for (int i = 0; i < columnCount; i++) {
            strArr[i] = databaseResults.getString(i);
        }
        return strArr;
    }

    public SelectIterator<T, ID> buildIterator(BaseDaoImpl<T, ID> baseDaoImpl, ConnectionSource connectionSource, PreparedStmt<T> preparedStmt, ObjectCache objectCache, int i) throws Throwable {
        Throwable th;
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        try {
            CompiledStatement compiledStatementCompile = preparedStmt.compile(readOnlyConnection, StatementBuilder.StatementType.SELECT, i);
            try {
                SelectIterator<T, ID> selectIterator = new SelectIterator<>(this.tableInfo.getDataClass(), baseDaoImpl, preparedStmt, connectionSource, readOnlyConnection, compiledStatementCompile, objectCache);
                IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
                return selectIterator;
            } catch (Throwable th2) {
                th = th2;
                compiledStatement = compiledStatementCompile;
                IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
                if (readOnlyConnection == null) {
                    throw th;
                }
                connectionSource.releaseConnection(readOnlyConnection);
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
        }
    }

    public int delete(DatabaseConnection databaseConnection, PreparedDelete<T> preparedDelete) throws SQLException {
        CompiledStatement compiledStatementCompile = preparedDelete.compile(databaseConnection, StatementBuilder.StatementType.DELETE);
        try {
            int iRunUpdate = compiledStatementCompile.runUpdate();
            if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
                this.dao.notifyChanges();
            }
            return iRunUpdate;
        } finally {
            IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
        }
    }

    public int update(DatabaseConnection databaseConnection, PreparedUpdate<T> preparedUpdate) throws SQLException {
        CompiledStatement compiledStatementCompile = preparedUpdate.compile(databaseConnection, StatementBuilder.StatementType.UPDATE);
        try {
            int iRunUpdate = compiledStatementCompile.runUpdate();
            if (this.dao != null && !this.localIsInBatchMode.get().booleanValue()) {
                this.dao.notifyChanges();
            }
            return iRunUpdate;
        } finally {
            IOUtils.closeThrowSqlException(compiledStatementCompile, "compiled statement");
        }
    }

    public long queryForLong(DatabaseConnection databaseConnection, String str, String[] strArr) throws Throwable {
        Throwable th;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for long: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        try {
            compiledStatementCompileStatement = databaseConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
        } catch (Throwable th2) {
            th = th2;
            compiledStatementCompileStatement = null;
        }
        try {
            assignStatementArguments(compiledStatementCompileStatement, strArr);
            DatabaseResults databaseResultsRunQuery = compiledStatementCompileStatement.runQuery(null);
            if (databaseResultsRunQuery.first()) {
                long j = databaseResultsRunQuery.getLong(0);
                IOUtils.closeThrowSqlException(databaseResultsRunQuery, "results");
                IOUtils.closeThrowSqlException(compiledStatementCompileStatement, "compiled statement");
                return j;
            }
            throw new SQLException("No result found in queryForLong: " + str);
        } catch (Throwable th3) {
            th = th3;
            IOUtils.closeThrowSqlException((AutoCloseable) null, "results");
            IOUtils.closeThrowSqlException(compiledStatementCompileStatement, "compiled statement");
            throw th;
        }
    }

    public <UO> GenericRawResults<UO> queryRaw(ConnectionSource connectionSource, String str, RawRowMapper<UO> rawRowMapper, String[] strArr, ObjectCache objectCache) throws Throwable {
        ConnectionSource connectionSource2;
        Throwable th;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        try {
            compiledStatementCompileStatement = readOnlyConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
            try {
                assignStatementArguments(compiledStatementCompileStatement, strArr);
                try {
                    connectionSource2 = connectionSource;
                } catch (Throwable th2) {
                    th = th2;
                    connectionSource2 = connectionSource;
                }
            } catch (Throwable th3) {
                th = th3;
                connectionSource2 = connectionSource;
            }
        } catch (Throwable th4) {
            connectionSource2 = connectionSource;
            th = th4;
        }
        try {
            RawResultsImpl rawResultsImpl = new RawResultsImpl(connectionSource2, readOnlyConnection, String[].class, compiledStatementCompileStatement, new UserRawRowMapper(rawRowMapper, this), objectCache);
            IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
            return rawResultsImpl;
        } catch (Throwable th5) {
            th = th5;
            readOnlyConnection = readOnlyConnection;
            th = th;
            compiledStatement = compiledStatementCompileStatement;
            IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
            if (readOnlyConnection == null) {
                throw th;
            }
            connectionSource2.releaseConnection(readOnlyConnection);
            throw th;
        }
    }

    private <CT> CT doCallBatchTasks(DatabaseConnection databaseConnection, boolean z, Callable<CT> callable) throws Throwable {
        boolean z2;
        Throwable th;
        if (this.databaseType.isBatchUseTransaction()) {
            return (CT) TransactionManager.callInTransaction(databaseConnection, z, this.databaseType, callable);
        }
        boolean z3 = false;
        try {
            if (databaseConnection.isAutoCommitSupported() && databaseConnection.isAutoCommit()) {
                databaseConnection.setAutoCommit(false);
                try {
                    logger.debug("disabled auto-commit on table {} before batch tasks", this.tableInfo.getTableName());
                    z3 = true;
                } catch (Throwable th2) {
                    th = th2;
                    z2 = true;
                    if (z2) {
                        databaseConnection.setAutoCommit(true);
                        logger.debug("re-enabled auto-commit on table {} after batch tasks", this.tableInfo.getTableName());
                    }
                    throw th;
                }
            }
            try {
                CT ctCall = callable.call();
                if (z3) {
                    databaseConnection.setAutoCommit(true);
                    logger.debug("re-enabled auto-commit on table {} after batch tasks", this.tableInfo.getTableName());
                }
                return ctCall;
            } catch (SQLException e) {
                throw e;
            } catch (Exception e2) {
                throw new SQLException("Batch tasks callable threw non-SQL exception", e2);
            }
        } catch (Throwable th3) {
            z2 = z3;
            th = th3;
        }
    }

    public <UO> GenericRawResults<UO> queryRaw(ConnectionSource connectionSource, String str, DataType[] dataTypeArr, RawRowObjectMapper<UO> rawRowObjectMapper, String[] strArr, ObjectCache objectCache) throws Throwable {
        DatabaseConnection databaseConnection;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        try {
            compiledStatementCompileStatement = readOnlyConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
            try {
                assignStatementArguments(compiledStatementCompileStatement, strArr);
                databaseConnection = readOnlyConnection;
            } catch (Throwable th) {
                th = th;
                databaseConnection = readOnlyConnection;
            }
        } catch (Throwable th2) {
            th = th2;
            databaseConnection = readOnlyConnection;
        }
        try {
            RawResultsImpl rawResultsImpl = new RawResultsImpl(connectionSource, databaseConnection, String[].class, compiledStatementCompileStatement, new UserRawRowObjectMapper(rawRowObjectMapper, dataTypeArr), objectCache);
            IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
            return rawResultsImpl;
        } catch (Throwable th3) {
            th = th3;
            compiledStatement = compiledStatementCompileStatement;
            IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
            if (databaseConnection != null) {
                connectionSource.releaseConnection(databaseConnection);
            }
            throw th;
        }
    }

    public GenericRawResults<Object[]> queryRaw(ConnectionSource connectionSource, String str, DataType[] dataTypeArr, String[] strArr, ObjectCache objectCache) throws Throwable {
        ConnectionSource connectionSource2;
        Throwable th;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        try {
            compiledStatementCompileStatement = readOnlyConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
            try {
                assignStatementArguments(compiledStatementCompileStatement, strArr);
                try {
                    connectionSource2 = connectionSource;
                } catch (Throwable th2) {
                    th = th2;
                    connectionSource2 = connectionSource;
                }
            } catch (Throwable th3) {
                th = th3;
                connectionSource2 = connectionSource;
            }
        } catch (Throwable th4) {
            connectionSource2 = connectionSource;
            th = th4;
        }
        try {
            RawResultsImpl rawResultsImpl = new RawResultsImpl(connectionSource2, readOnlyConnection, Object[].class, compiledStatementCompileStatement, new ObjectArrayRowMapper(dataTypeArr), objectCache);
            IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
            return rawResultsImpl;
        } catch (Throwable th5) {
            th = th5;
            readOnlyConnection = readOnlyConnection;
            th = th;
            compiledStatement = compiledStatementCompileStatement;
            IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
            if (readOnlyConnection == null) {
                throw th;
            }
            connectionSource2.releaseConnection(readOnlyConnection);
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public <UO> GenericRawResults<UO> queryRaw(ConnectionSource connectionSource, String str, DatabaseResultsMapper<UO> databaseResultsMapper, String[] strArr, ObjectCache objectCache) throws Throwable {
        ConnectionSource connectionSource2;
        Throwable th;
        CompiledStatement compiledStatementCompileStatement;
        logger.debug("executing raw query for: {}", str);
        if (strArr.length > 0) {
            logger.trace("query arguments: {}", (Object) strArr);
        }
        DatabaseConnection readOnlyConnection = connectionSource.getReadOnlyConnection(this.tableInfo.getTableName());
        CompiledStatement compiledStatement = null;
        Object[] objArr = 0;
        try {
            compiledStatementCompileStatement = readOnlyConnection.compileStatement(str, StatementBuilder.StatementType.SELECT, noFieldTypes, -1, false);
            try {
                assignStatementArguments(compiledStatementCompileStatement, strArr);
                try {
                    connectionSource2 = connectionSource;
                } catch (Throwable th2) {
                    th = th2;
                    connectionSource2 = connectionSource;
                }
            } catch (Throwable th3) {
                th = th3;
                connectionSource2 = connectionSource;
            }
        } catch (Throwable th4) {
            connectionSource2 = connectionSource;
            th = th4;
        }
        try {
            RawResultsImpl rawResultsImpl = new RawResultsImpl(connectionSource2, readOnlyConnection, Object[].class, compiledStatementCompileStatement, new UserDatabaseResultsMapper(databaseResultsMapper), objectCache);
            IOUtils.closeThrowSqlException((AutoCloseable) null, "compiled statement");
            return rawResultsImpl;
        } catch (Throwable th5) {
            th = th5;
            readOnlyConnection = readOnlyConnection;
            th = th;
            compiledStatement = compiledStatementCompileStatement;
            IOUtils.closeThrowSqlException(compiledStatement, "compiled statement");
            if (readOnlyConnection == null) {
                throw th;
            }
            connectionSource2.releaseConnection(readOnlyConnection);
            throw th;
        }
    }
}
