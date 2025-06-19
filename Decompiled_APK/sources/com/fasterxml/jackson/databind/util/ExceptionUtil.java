package com.fasterxml.jackson.databind.util;

import java.io.IOException;

/* loaded from: classes.dex */
public abstract class ExceptionUtil {
    private static <E extends Throwable> void _sneaky(Throwable th) throws Throwable {
        throw th;
    }

    private static boolean isFatal(Throwable th) {
        return (th instanceof VirtualMachineError) || (th instanceof ThreadDeath) || (th instanceof InterruptedException) || (th instanceof ClassCircularityError) || (th instanceof ClassFormatError) || (th instanceof IncompatibleClassChangeError) || (th instanceof BootstrapMethodError) || (th instanceof VerifyError);
    }

    public static void rethrowIfFatal(Throwable th) throws Error, RuntimeException {
        if (isFatal(th)) {
            if (th instanceof Error) {
                throw ((Error) th);
            }
            if (!(th instanceof RuntimeException)) {
                throw new RuntimeException(th);
            }
            throw ((RuntimeException) th);
        }
    }

    public static <T> T throwSneaky(IOException iOException) throws Throwable {
        _sneaky(iOException);
        return null;
    }
}
