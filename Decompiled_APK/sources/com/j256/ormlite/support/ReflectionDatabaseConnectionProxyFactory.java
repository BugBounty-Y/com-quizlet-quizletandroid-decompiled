package com.j256.ormlite.support;

import androidx.compose.ui.node.B;
import java.lang.reflect.Constructor;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public class ReflectionDatabaseConnectionProxyFactory implements DatabaseConnectionProxyFactory {
    private final Constructor<? extends DatabaseConnection> constructor;
    private final Class<? extends DatabaseConnection> proxyClass;

    public ReflectionDatabaseConnectionProxyFactory(Class<? extends DatabaseConnection> cls) throws IllegalArgumentException {
        this.proxyClass = cls;
        try {
            this.constructor = cls.getConstructor(DatabaseConnection.class);
        } catch (Exception unused) {
            throw new IllegalArgumentException(B.d(cls, "Could not find constructor with DatabaseConnection argument in "));
        }
    }

    @Override // com.j256.ormlite.support.DatabaseConnectionProxyFactory
    public DatabaseConnection createProxy(DatabaseConnection databaseConnection) throws SQLException {
        try {
            return this.constructor.newInstance(databaseConnection);
        } catch (Exception e) {
            throw new SQLException("Could not create a new instance of " + this.proxyClass, e);
        }
    }
}
