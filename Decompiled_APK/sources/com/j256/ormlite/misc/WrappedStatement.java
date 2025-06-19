package com.j256.ormlite.misc;

import com.j256.ormlite.logger.Logger;
import com.j256.ormlite.logger.LoggerFactory;
import com.j256.ormlite.support.CompiledStatement;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/* loaded from: classes2.dex */
public class WrappedStatement implements InvocationHandler {
    private static final Logger logger = LoggerFactory.getLogger((Class<?>) WrappedStatement.class);
    private boolean closeCalled;
    private final CompiledStatement statement;
    private final CompiledStatement statementProxy = (CompiledStatement) Proxy.newProxyInstance(getClass().getClassLoader(), new Class[]{CompiledStatement.class}, this);

    public WrappedStatement(CompiledStatement compiledStatement) {
        this.statement = compiledStatement;
    }

    public CompiledStatement getStatementProxy() {
        return this.statementProxy;
    }

    @Override // java.lang.reflect.InvocationHandler
    public Object invoke(Object obj, Method method, Object[] objArr) throws Throwable {
        logger.trace("{}: running method on statement: {}", this, method.getName());
        try {
            Object objInvoke = method.invoke(this.statement, objArr);
            if (!method.getName().equals("close")) {
                return objInvoke;
            }
            this.closeCalled = true;
            return objInvoke;
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }
    }

    public boolean isClosed() {
        if (this.closeCalled) {
            return true;
        }
        logger.error("{}: CompiledStatement was not closed: {}", this, this.statement);
        return false;
    }
}
