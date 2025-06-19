package com.j256.ormlite.misc;

import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public class TransactionManager {
    private static final String SAVE_POINT_PREFIX = "ORMLITE";
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) TransactionManager.class);
    private static final AtomicInteger savePointCounter = new AtomicInteger();
    private static final ThreadLocal<TransactionLevel> transactionLevelThreadLocal = new ThreadLocal<TransactionLevel>() { // from class: com.j256.ormlite.misc.TransactionManager.1
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // java.lang.ThreadLocal
        public TransactionLevel initialValue() {
            return new TransactionLevel();
        }
    };
    private ConnectionSource connectionSource;

    public static class TransactionLevel {
        int counter;

        private TransactionLevel() {
        }

        public int decrementAndGet() {
            int i = this.counter - 1;
            this.counter = i;
            return i;
        }

        public int incrementAndGet() {
            int i = this.counter + 1;
            this.counter = i;
            return i;
        }
    }

    public TransactionManager() {
    }

    private static void commit(DatabaseConnection databaseConnection, Savepoint savepoint) throws SQLException {
        String savepointName = savepoint == null ? null : savepoint.getSavepointName();
        databaseConnection.commit(savepoint);
        if (savepointName == null) {
            logger.trace("committed savePoint transaction");
        } else {
            logger.trace("committed savePoint transaction {}", savepointName);
        }
    }

    private static void release(DatabaseConnection databaseConnection, Savepoint savepoint) throws SQLException {
        String savepointName = savepoint == null ? null : savepoint.getSavepointName();
        databaseConnection.releaseSavePoint(savepoint);
        if (savepointName == null) {
            logger.trace("released savePoint transaction");
        } else {
            logger.trace("released savePoint transaction {}", savepointName);
        }
    }

    private static void rollBack(DatabaseConnection databaseConnection, Savepoint savepoint) throws SQLException {
        String savepointName = savepoint == null ? null : savepoint.getSavepointName();
        databaseConnection.rollback(savepoint);
        if (savepointName == null) {
            logger.trace("rolled back savePoint transaction");
        } else {
            logger.trace("rolled back savePoint transaction {}", savepointName);
        }
    }

    public <T> T callInTransaction(Callable<T> callable) throws SQLException {
        return (T) callInTransaction(this.connectionSource, callable);
    }

    public void initialize() {
        if (this.connectionSource == null) {
            throw new IllegalStateException("dataSource was not set on ".concat(getClass().getSimpleName()));
        }
    }

    public void setConnectionSource(ConnectionSource connectionSource) {
        this.connectionSource = connectionSource;
    }

    public TransactionManager(ConnectionSource connectionSource) {
        this.connectionSource = connectionSource;
        initialize();
    }

    public <T> T callInTransaction(String str, Callable<T> callable) throws SQLException {
        return (T) callInTransaction(str, this.connectionSource, callable);
    }

    public static <T> T callInTransaction(ConnectionSource connectionSource, Callable<T> callable) throws SQLException {
        return (T) callInTransaction((String) null, connectionSource, callable);
    }

    public static <T> T callInTransaction(String str, ConnectionSource connectionSource, Callable<T> callable) throws Throwable {
        boolean zSaveSpecialConnection;
        DatabaseConnection readWriteConnection = connectionSource.getReadWriteConnection(str);
        try {
            zSaveSpecialConnection = connectionSource.saveSpecialConnection(readWriteConnection);
            try {
                T t = (T) callInTransaction(readWriteConnection, zSaveSpecialConnection, connectionSource.getDatabaseType(), callable);
                if (zSaveSpecialConnection) {
                    connectionSource.clearSpecialConnection(readWriteConnection);
                }
                connectionSource.releaseConnection(readWriteConnection);
                return t;
            } catch (Throwable th) {
                th = th;
                if (zSaveSpecialConnection) {
                    connectionSource.clearSpecialConnection(readWriteConnection);
                }
                connectionSource.releaseConnection(readWriteConnection);
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
            zSaveSpecialConnection = false;
        }
    }

    public static <T> T callInTransaction(DatabaseConnection databaseConnection, DatabaseType databaseType, Callable<T> callable) throws SQLException {
        return (T) callInTransaction(databaseConnection, false, databaseType, callable);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0052 A[Catch: all -> 0x001b, TryCatch #3 {all -> 0x001b, blocks: (B:4:0x0011, B:10:0x001e, B:12:0x0024, B:14:0x002a, B:19:0x003a, B:21:0x0052, B:22:0x005a), top: B:60:0x0011 }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005a A[Catch: all -> 0x001b, TRY_LEAVE, TryCatch #3 {all -> 0x001b, blocks: (B:4:0x0011, B:10:0x001e, B:12:0x0024, B:14:0x002a, B:19:0x003a, B:21:0x0052, B:22:0x005a), top: B:60:0x0011 }] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x008b  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0074 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static <T> T callInTransaction(com.j256.ormlite.support.DatabaseConnection r8, boolean r9, com.j256.ormlite.db.DatabaseType r10, java.util.concurrent.Callable<T> r11) throws java.lang.Throwable {
        /*
            java.lang.String r0 = "ORMLITE"
            java.lang.ThreadLocal<com.j256.ormlite.misc.TransactionManager$TransactionLevel> r1 = com.j256.ormlite.misc.TransactionManager.transactionLevelThreadLocal
            java.lang.Object r2 = r1.get()
            com.j256.ormlite.misc.TransactionManager$TransactionLevel r2 = (com.j256.ormlite.misc.TransactionManager.TransactionLevel) r2
            java.lang.String r3 = "restored auto-commit to true"
            r4 = 0
            r5 = 1
            r6 = 0
            if (r9 != 0) goto L1e
            boolean r9 = r10.isNestedSavePointsSupported()     // Catch: java.lang.Throwable -> L1b
            if (r9 == 0) goto L18
            goto L1e
        L18:
            r9 = r4
            r10 = r6
            goto L67
        L1b:
            r9 = move-exception
            goto Lbe
        L1e:
            boolean r9 = r8.isAutoCommitSupported()     // Catch: java.lang.Throwable -> L1b
            if (r9 == 0) goto L3a
            boolean r9 = r8.isAutoCommit()     // Catch: java.lang.Throwable -> L1b
            if (r9 == 0) goto L3a
            r8.setAutoCommit(r6)     // Catch: java.lang.Throwable -> L1b
            com.j256.ormlite.logger.Logger r9 = com.j256.ormlite.misc.TransactionManager.logger     // Catch: java.lang.Throwable -> L36
            java.lang.String r10 = "had to set auto-commit to false"
            r9.trace(r10)     // Catch: java.lang.Throwable -> L36
            r6 = r5
            goto L3a
        L36:
            r9 = move-exception
            r6 = r5
            goto Lbe
        L3a:
            java.lang.StringBuilder r9 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L1b
            r9.<init>(r0)     // Catch: java.lang.Throwable -> L1b
            java.util.concurrent.atomic.AtomicInteger r10 = com.j256.ormlite.misc.TransactionManager.savePointCounter     // Catch: java.lang.Throwable -> L1b
            int r10 = r10.incrementAndGet()     // Catch: java.lang.Throwable -> L1b
            r9.append(r10)     // Catch: java.lang.Throwable -> L1b
            java.lang.String r9 = r9.toString()     // Catch: java.lang.Throwable -> L1b
            java.sql.Savepoint r9 = r8.setSavePoint(r9)     // Catch: java.lang.Throwable -> L1b
            if (r9 != 0) goto L5a
            com.j256.ormlite.logger.Logger r10 = com.j256.ormlite.misc.TransactionManager.logger     // Catch: java.lang.Throwable -> L1b
            java.lang.String r0 = "started savePoint transaction"
            r10.trace(r0)     // Catch: java.lang.Throwable -> L1b
            goto L65
        L5a:
            com.j256.ormlite.logger.Logger r10 = com.j256.ormlite.misc.TransactionManager.logger     // Catch: java.lang.Throwable -> L1b
            java.lang.String r0 = "started savePoint transaction {}"
            java.lang.String r7 = r9.getSavepointName()     // Catch: java.lang.Throwable -> L1b
            r10.trace(r0, r7)     // Catch: java.lang.Throwable -> L1b
        L65:
            r10 = r6
            r6 = r5
        L67:
            r2.incrementAndGet()     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L94
            java.lang.Object r11 = r11.call()     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L94
            int r0 = r2.decrementAndGet()     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L94
            if (r0 > 0) goto L7e
            r1.remove()     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L7b
            goto L7e
        L78:
            r9 = move-exception
            r6 = r10
            goto Lbe
        L7b:
            r11 = move-exception
            r2 = r4
            goto L95
        L7e:
            if (r6 == 0) goto L89
            if (r0 > 0) goto L86
            commit(r8, r9)     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L7b
            goto L89
        L86:
            release(r8, r9)     // Catch: java.lang.Throwable -> L78 java.lang.Exception -> L7b
        L89:
            if (r10 == 0) goto L93
            r8.setAutoCommit(r5)
            com.j256.ormlite.logger.Logger r8 = com.j256.ormlite.misc.TransactionManager.logger
            r8.trace(r3)
        L93:
            return r11
        L94:
            r11 = move-exception
        L95:
            if (r2 == 0) goto La2
            int r0 = r2.decrementAndGet()     // Catch: java.lang.Throwable -> L78
            if (r0 > 0) goto La2
            java.lang.ThreadLocal<com.j256.ormlite.misc.TransactionManager$TransactionLevel> r0 = com.j256.ormlite.misc.TransactionManager.transactionLevelThreadLocal     // Catch: java.lang.Throwable -> L78
            r0.remove()     // Catch: java.lang.Throwable -> L78
        La2:
            if (r6 == 0) goto Laf
            rollBack(r8, r9)     // Catch: java.lang.Throwable -> L78 java.sql.SQLException -> La8
            goto Laf
        La8:
            com.j256.ormlite.logger.Logger r9 = com.j256.ormlite.misc.TransactionManager.logger     // Catch: java.lang.Throwable -> L78
            java.lang.String r0 = "after commit exception, rolling back to save-point also threw exception"
            r9.error(r11, r0)     // Catch: java.lang.Throwable -> L78
        Laf:
            boolean r9 = r11 instanceof java.sql.SQLException     // Catch: java.lang.Throwable -> L78
            if (r9 == 0) goto Lb6
            java.sql.SQLException r11 = (java.sql.SQLException) r11     // Catch: java.lang.Throwable -> L78
            throw r11     // Catch: java.lang.Throwable -> L78
        Lb6:
            java.sql.SQLException r9 = new java.sql.SQLException     // Catch: java.lang.Throwable -> L78
            java.lang.String r0 = "Transaction callable threw non-SQL exception"
            r9.<init>(r0, r11)     // Catch: java.lang.Throwable -> L78
            throw r9     // Catch: java.lang.Throwable -> L78
        Lbe:
            if (r6 == 0) goto Lc8
            r8.setAutoCommit(r5)
            com.j256.ormlite.logger.Logger r8 = com.j256.ormlite.misc.TransactionManager.logger
            r8.trace(r3)
        Lc8:
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.j256.ormlite.misc.TransactionManager.callInTransaction(com.j256.ormlite.support.DatabaseConnection, boolean, com.j256.ormlite.db.DatabaseType, java.util.concurrent.Callable):java.lang.Object");
    }
}
