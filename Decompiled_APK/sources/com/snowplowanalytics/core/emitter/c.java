package com.snowplowanalytics.core.emitter;

import com.google.firebase.messaging.s;
import com.snowplowanalytics.core.tracker.e;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static ScheduledExecutorService a;
    public static int b = b.h;

    public static final void a(boolean z, String str, Runnable runnable) {
        s sVar = new s(z, str);
        ExecutorService executorServiceC = c();
        if (executorServiceC != null) {
            try {
                executorServiceC.execute(new com.skydoves.balloon.compose.a(2, runnable, sVar));
            } catch (Exception e) {
                sVar.a(e);
            }
        }
    }

    public static final Future b(Callable callable) {
        Intrinsics.checkNotNullParameter(callable, "callable");
        try {
            ExecutorService executorServiceC = c();
            if (executorServiceC != null) {
                return executorServiceC.submit(callable);
            }
            return null;
        } catch (Exception e) {
            String message = e.getMessage();
            if (message == null) {
                message = "Failed to submit task";
            }
            e.b("Executor", message, new Object[0]);
            return null;
        }
    }

    public static final synchronized ExecutorService c() {
        if (a == null) {
            try {
                a = Executors.newScheduledThreadPool(b);
            } catch (Exception e) {
                String message = e.getMessage();
                if (message == null) {
                    message = "Failed to create thread pool";
                }
                e.b("Executor", message, new Object[0]);
            }
        }
        return a;
    }
}
