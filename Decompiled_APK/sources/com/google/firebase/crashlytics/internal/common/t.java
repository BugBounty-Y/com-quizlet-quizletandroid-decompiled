package com.google.firebase.crashlytics.internal.common;

import android.os.Process;
import android.util.Log;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class t implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Object b;

    public t(Runnable runnable) {
        this.b = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() throws SecurityException, IllegalArgumentException {
        Process.setThreadPriority(10);
        switch (this.a) {
            case 0:
                ((Runnable) this.b).run();
                break;
            default:
                ExecutorService executorService = (ExecutorService) this.b;
                try {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    executorService.shutdown();
                    if (!executorService.awaitTermination(2L, TimeUnit.SECONDS)) {
                        Log.isLoggable("FirebaseCrashlytics", 3);
                        executorService.shutdownNow();
                        break;
                    }
                } catch (InterruptedException unused) {
                    Locale locale = Locale.US;
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    executorService.shutdownNow();
                    return;
                }
                break;
        }
    }

    public t(ExecutorService executorService) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        this.b = executorService;
    }
}
