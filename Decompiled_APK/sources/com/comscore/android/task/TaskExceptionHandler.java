package com.comscore.android.task;

/* loaded from: classes.dex */
public interface TaskExceptionHandler {
    void exception(Exception exc, TaskExecutor taskExecutor, Runnable runnable);
}
