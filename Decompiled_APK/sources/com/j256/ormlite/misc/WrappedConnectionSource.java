package com.j256.ormlite.misc;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import com.j256.ormlite.db.DatabaseType;
import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public class WrappedConnectionSource implements ConnectionSource {
    protected static final Logger logger = LoggerFactory.getLogger((Class<?>) WrappedConnectionSource.class);
    protected final ConnectionSource cs;
    protected boolean nextForceOkay;
    private final AtomicInteger connectionCount = new AtomicInteger(0);
    private final Map<DatabaseConnection, WrappedDatabaseConnection> wrappedConnections = new HashMap();

    public WrappedConnectionSource(ConnectionSource connectionSource) {
        this.cs = connectionSource;
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public void clearSpecialConnection(DatabaseConnection databaseConnection) {
        this.cs.clearSpecialConnection(databaseConnection);
    }

    @Override // java.lang.AutoCloseable
    public void close() throws Exception {
        boolean zIsTerminated;
        AutoCloseable autoCloseable = this.cs;
        if (autoCloseable instanceof AutoCloseable) {
            autoCloseable.close();
        } else if (autoCloseable instanceof ExecutorService) {
            ExecutorService executorService = (ExecutorService) autoCloseable;
            if (executorService != ForkJoinPool.commonPool() && !(zIsTerminated = executorService.isTerminated())) {
                executorService.shutdown();
                boolean z = false;
                while (!zIsTerminated) {
                    try {
                        zIsTerminated = executorService.awaitTermination(1L, TimeUnit.DAYS);
                    } catch (InterruptedException unused) {
                        if (!z) {
                            executorService.shutdownNow();
                            z = true;
                        }
                    }
                }
                if (z) {
                    Thread.currentThread().interrupt();
                }
            }
        } else if (autoCloseable instanceof TypedArray) {
            ((TypedArray) autoCloseable).recycle();
        } else if (autoCloseable instanceof MediaMetadataRetriever) {
            ((MediaMetadataRetriever) autoCloseable).release();
        } else {
            if (!(autoCloseable instanceof MediaDrm)) {
                throw new IllegalArgumentException();
            }
            ((MediaDrm) autoCloseable).release();
        }
        if (!isEverythingClosed()) {
            throw new SQLException("Wrapped connections were not fully closed when connection-source closed");
        }
        Iterator<WrappedDatabaseConnection> it2 = this.wrappedConnections.values().iterator();
        while (it2.hasNext()) {
            it2.next().close();
        }
        this.wrappedConnections.clear();
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public void closeQuietly() {
        IOUtils.closeQuietly(this);
    }

    public void forceOkay() {
        this.nextForceOkay = true;
    }

    public int getConnectionCount() {
        return this.connectionCount.get();
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public DatabaseType getDatabaseType() {
        return this.cs.getDatabaseType();
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public DatabaseConnection getReadOnlyConnection(String str) throws SQLException {
        DatabaseConnection readOnlyConnection = this.cs.getReadOnlyConnection(str);
        this.connectionCount.incrementAndGet();
        WrappedDatabaseConnection wrappedDatabaseConnection = new WrappedDatabaseConnection(readOnlyConnection);
        DatabaseConnection databaseConnectionProxy = wrappedDatabaseConnection.getDatabaseConnectionProxy();
        this.wrappedConnections.put(databaseConnectionProxy, wrappedDatabaseConnection);
        logger.trace("{}: got wrapped read-only DatabaseConnection '{}', count = {}", this, wrappedDatabaseConnection, this.connectionCount);
        return databaseConnectionProxy;
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public DatabaseConnection getReadWriteConnection(String str) throws SQLException {
        DatabaseConnection readWriteConnection = this.cs.getReadWriteConnection(str);
        this.connectionCount.incrementAndGet();
        WrappedDatabaseConnection wrappedDatabaseConnection = new WrappedDatabaseConnection(readWriteConnection);
        DatabaseConnection databaseConnectionProxy = wrappedDatabaseConnection.getDatabaseConnectionProxy();
        this.wrappedConnections.put(databaseConnectionProxy, wrappedDatabaseConnection);
        logger.trace("{}: got wrapped read-write DatabaseConnection '{}', count = {}", this, wrappedDatabaseConnection, this.connectionCount);
        return databaseConnectionProxy;
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public DatabaseConnection getSpecialConnection(String str) {
        return this.cs.getSpecialConnection(str);
    }

    public boolean isEverythingClosed() {
        if (this.nextForceOkay) {
            this.nextForceOkay = false;
            return true;
        }
        if (this.connectionCount.get() == 0) {
            Iterator<WrappedDatabaseConnection> it2 = this.wrappedConnections.values().iterator();
            while (it2.hasNext()) {
                if (!it2.next().isAllStatementsClosed()) {
                    return false;
                }
            }
            return true;
        }
        logger.error("{}: ConnectionSource has {} open connections", this, this.connectionCount);
        Iterator<WrappedDatabaseConnection> it3 = this.wrappedConnections.values().iterator();
        while (it3.hasNext()) {
            logger.error("{}: still has wrapped DatabaseConnection '{}'", this, it3.next());
        }
        return false;
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public boolean isOpen(String str) {
        return this.cs.isOpen(str);
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public boolean isSingleConnection(String str) {
        return this.cs.isSingleConnection(str);
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public void releaseConnection(DatabaseConnection databaseConnection) throws SQLException {
        WrappedDatabaseConnection wrappedDatabaseConnectionRemove = this.wrappedConnections.remove(databaseConnection);
        if (wrappedDatabaseConnectionRemove == null) {
            if (this.nextForceOkay) {
                return;
            }
            throw new SQLException("Tried to release unknown connection: " + databaseConnection);
        }
        if (!wrappedDatabaseConnectionRemove.isAllStatementsClosed()) {
            throw new SQLException("Wrapped connection had open statements when released: " + wrappedDatabaseConnectionRemove);
        }
        this.cs.releaseConnection(wrappedDatabaseConnectionRemove.getDatabaseConnection());
        wrappedDatabaseConnectionRemove.close();
        this.connectionCount.decrementAndGet();
        logger.trace("{}: released wrapped DatabaseConnection '{}', count = {}", this, wrappedDatabaseConnectionRemove, this.connectionCount);
    }

    @Override // com.j256.ormlite.support.ConnectionSource
    public boolean saveSpecialConnection(DatabaseConnection databaseConnection) throws SQLException {
        return this.cs.saveSpecialConnection(databaseConnection);
    }

    public void setDatabaseType(DatabaseType databaseType) throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        try {
            this.cs.getClass().getMethod("setDatabaseType", DatabaseType.class).invoke(this.cs, databaseType);
        } catch (Exception e) {
            throw new RuntimeException("Could not set database type", e);
        }
    }
}
