package org.prebid.mobile.tasksmanager;

/* loaded from: classes3.dex */
public class TasksManager {
    public static TasksManager b;
    public final BackgroundThreadExecutor a;

    private TasksManager() {
        new MainThreadExecutor();
        this.a = new BackgroundThreadExecutor();
    }

    public static synchronized TasksManager a() {
        try {
            if (b == null) {
                synchronized (TasksManager.class) {
                    b = new TasksManager();
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return b;
    }
}
