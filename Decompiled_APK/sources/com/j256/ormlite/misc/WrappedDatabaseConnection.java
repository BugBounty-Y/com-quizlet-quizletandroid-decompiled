package com.j256.ormlite.misc;

import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.DatabaseConnection;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public class WrappedDatabaseConnection implements InvocationHandler {
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) WrappedDatabaseConnection.class);
    protected final DatabaseConnection connection;
    protected final List<WrappedStatement> wrappedStatements = new ArrayList();
    protected final DatabaseConnection connectionProxy = (DatabaseConnection) Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{DatabaseConnection.class}, this);

    public WrappedDatabaseConnection(DatabaseConnection databaseConnection) {
        this.connection = databaseConnection;
    }

    public void close() {
        this.wrappedStatements.clear();
    }

    public DatabaseConnection getDatabaseConnection() {
        return this.connection;
    }

    public DatabaseConnection getDatabaseConnectionProxy() {
        return this.connectionProxy;
    }

    @Override // java.lang.reflect.InvocationHandler
    public Object invoke(Object obj, Method method, Object[] objArr) throws Throwable {
        Logger logger2 = logger;
        logger2.trace("{}: running method on connection: {}", this, method.getName());
        try {
            Object objInvoke = method.invoke(this.connection, objArr);
            if (!method.getName().equals("compileStatement") || !(objInvoke instanceof CompiledStatement)) {
                return objInvoke;
            }
            WrappedStatement wrappedStatement = new WrappedStatement((CompiledStatement) objInvoke);
            this.wrappedStatements.add(wrappedStatement);
            logger2.trace("{}: connection is wrapping statement: {}", this, objInvoke);
            return wrappedStatement.getStatementProxy();
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    public boolean isAllStatementsClosed() {
        Iterator<WrappedStatement> it2 = this.wrappedStatements.iterator();
        while (it2.hasNext()) {
            if (!it2.next().isClosed()) {
                return false;
            }
        }
        return true;
    }
}
