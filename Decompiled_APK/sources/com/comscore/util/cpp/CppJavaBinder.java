package com.comscore.util.cpp;

import com.comscore.util.log.Logger;
import com.comscore.util.setup.Setup;

/* loaded from: classes.dex */
public abstract class CppJavaBinder {
    private int a = 0;

    static {
        Setup.setUp();
    }

    public abstract void destroyCppObject();

    public void finalize() throws Throwable {
        super.finalize();
        destroyCppObject();
    }

    public int getExceptionCounter() {
        return this.a;
    }

    public void printException(Throwable th) {
        Logger.e("Error using the native library: ", th);
        this.a++;
    }
}
