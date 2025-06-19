package com.google.firebase.crashlytics.internal.concurrency;

import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public final class b implements Executor {
    public final ExecutorService a;
    public final Object b = new Object();
    public Task c = S3.i(null);

    public b(ExecutorService executorService) {
        this.a = executorService;
    }

    public final Task a(Runnable runnable) {
        Task taskF;
        synchronized (this.b) {
            taskF = this.c.f(this.a, new com.google.android.material.search.a(runnable, 9));
            this.c = taskF;
        }
        return taskF;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        this.a.execute(runnable);
    }
}
