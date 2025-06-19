package androidx.work;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class T {
    public abstract y a(Context context, String str, WorkerParameters workerParameters);

    public final y b(Context appContext, String workerClassName, WorkerParameters workerParameters) {
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(workerClassName, "workerClassName");
        Intrinsics.checkNotNullParameter(workerParameters, "workerParameters");
        y yVarA = a(appContext, workerClassName, workerParameters);
        if (yVarA == null) {
            try {
                Class<? extends U> clsAsSubclass = Class.forName(workerClassName).asSubclass(y.class);
                Intrinsics.checkNotNullExpressionValue(clsAsSubclass, "{\n                Class.…class.java)\n            }");
                try {
                    Object objNewInstance = clsAsSubclass.getDeclaredConstructor(Context.class, WorkerParameters.class).newInstance(appContext, workerParameters);
                    Intrinsics.checkNotNullExpressionValue(objNewInstance, "{\n                val co…Parameters)\n            }");
                    yVarA = (y) objNewInstance;
                } catch (Throwable th) {
                    z.c().b(U.a, "Could not instantiate " + workerClassName, th);
                    throw th;
                }
            } catch (Throwable th2) {
                z.c().b(U.a, "Invalid class: " + workerClassName, th2);
                throw th2;
            }
        }
        if (!yVarA.isUsed()) {
            return yVarA;
        }
        throw new IllegalStateException("WorkerFactory (" + getClass().getName() + ") returned an instance of a ListenableWorker (" + workerClassName + ") which has already been invoked. createWorker() must always return a new instance of a ListenableWorker.");
    }
}
