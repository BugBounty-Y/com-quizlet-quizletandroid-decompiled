package org.prebid.mobile.tasksmanager;

import android.os.Handler;
import android.os.HandlerThread;
import java.util.concurrent.Executor;

/* loaded from: classes3.dex */
public class BackgroundThreadExecutor implements Executor {
    public final Handler a;
    public final boolean b;

    public BackgroundThreadExecutor() {
        this.b = false;
        HandlerThread handlerThread = new HandlerThread("BackgroundThread");
        handlerThread.start();
        this.a = new Handler(handlerThread.getLooper());
        this.b = true;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        if (this.b) {
            this.a.post(runnable);
        }
    }
}
