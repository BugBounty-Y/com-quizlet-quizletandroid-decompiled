package com.comscore.android.task;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/* loaded from: classes.dex */
public class TaskExecutor {
    private static final long e = 50000;
    private com.comscore.android.task.b a;
    private BlockingQueue<com.comscore.android.task.a> b;
    private boolean c;
    private TaskExceptionHandler d;

    public class a implements TaskExceptionHandler {
        @Override // com.comscore.android.task.TaskExceptionHandler
        public void exception(Exception exc, TaskExecutor taskExecutor, Runnable runnable) {
            exc.printStackTrace();
        }
    }

    public class b implements Runnable {
        final /* synthetic */ Runnable a;

        public b(Runnable runnable) {
            this.a = runnable;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.a.run();
            } catch (Exception e) {
                TaskExecutor taskExecutor = TaskExecutor.this;
                TaskExceptionHandler taskExceptionHandler = taskExecutor.d;
                if (taskExceptionHandler != null) {
                    taskExceptionHandler.exception(e, taskExecutor, this.a);
                }
            }
        }
    }

    public TaskExecutor(TaskExceptionHandler taskExceptionHandler) {
        this.c = true;
        this.d = taskExceptionHandler;
        this.b = new LinkedBlockingQueue();
        com.comscore.android.task.b bVar = new com.comscore.android.task.b(this, this.d);
        this.a = bVar;
        bVar.start();
    }

    public long b() {
        Iterator<com.comscore.android.task.a> it2 = this.b.iterator();
        long jMin = e;
        while (it2.hasNext()) {
            jMin = Math.min(jMin, it2.next().d());
        }
        return jMin;
    }

    public boolean containsTask(Runnable runnable) {
        for (com.comscore.android.task.a aVar : this.b) {
            if (aVar.f() == runnable) {
                return true;
            }
            if ((runnable instanceof com.comscore.android.task.a) && aVar == runnable) {
                return true;
            }
        }
        return false;
    }

    public boolean execute(Runnable runnable) {
        return execute(runnable, true);
    }

    public boolean executeInMainThread(Runnable runnable) {
        if (this.c) {
            return new Handler(Looper.getMainLooper()).post(new b(runnable));
        }
        return false;
    }

    public boolean isEnabled() {
        return this.c;
    }

    public void removeAllEnqueuedTasks() {
        ArrayList arrayList = new ArrayList();
        for (com.comscore.android.task.a aVar : this.b) {
            if (aVar.g()) {
                arrayList.add(aVar);
            }
        }
        this.b.removeAll(arrayList);
    }

    public boolean removeEnqueuedTask(Runnable runnable) {
        if (runnable == null) {
            return false;
        }
        for (com.comscore.android.task.a aVar : this.b) {
            if (aVar.f() == runnable) {
                return this.b.remove(aVar);
            }
        }
        return false;
    }

    public void setEnabled(boolean z) {
        this.c = z;
    }

    public int size() {
        return this.b.size();
    }

    public void waitForLastNonDelayedTaskToFinish() throws InterruptedException {
        com.comscore.android.task.a aVar;
        int size = this.b.size();
        com.comscore.android.task.a[] aVarArr = new com.comscore.android.task.a[size];
        this.b.toArray(aVarArr);
        int i = size - 1;
        while (true) {
            if (i >= 0) {
                com.comscore.android.task.a aVar2 = aVarArr[i];
                if (aVar2 != null && !aVar2.h()) {
                    aVar = aVarArr[i];
                    break;
                }
                i--;
            } else {
                aVar = null;
                break;
            }
        }
        waitForTaskToFinish(aVar, 0L);
    }

    public void waitForTaskToFinish(Runnable runnable, long j) throws InterruptedException {
        com.comscore.android.task.a next;
        if (!(runnable instanceof com.comscore.android.task.a)) {
            Iterator<com.comscore.android.task.a> it2 = this.b.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    next = null;
                    break;
                } else {
                    next = it2.next();
                    if (next.f() == runnable) {
                        break;
                    }
                }
            }
        } else {
            next = (com.comscore.android.task.a) runnable;
        }
        if (next != null) {
            long jCurrentTimeMillis = System.currentTimeMillis();
            while (this.b.contains(next)) {
                if (j > 0 && System.currentTimeMillis() >= jCurrentTimeMillis + j) {
                    return;
                }
                try {
                    Thread.sleep(100L);
                } catch (InterruptedException e2) {
                    e2.printStackTrace();
                }
            }
        }
    }

    public void waitForTasks() throws InterruptedException {
        while (this.b.size() != 0) {
            try {
                Thread.sleep(100L);
            } catch (InterruptedException e2) {
                e2.printStackTrace();
            }
        }
    }

    public com.comscore.android.task.a a() {
        for (com.comscore.android.task.a aVar : this.b) {
            if (aVar.c() <= System.currentTimeMillis()) {
                return aVar;
            }
        }
        return null;
    }

    public boolean execute(Runnable runnable, boolean z) {
        if (z) {
            return execute(runnable, 0L);
        }
        if (!this.c) {
            return false;
        }
        try {
            runnable.run();
            return true;
        } catch (Exception e2) {
            if (this.d == null) {
                return true;
            }
            this.d.exception(e2, this, runnable);
            return true;
        }
    }

    public void a(com.comscore.android.task.a aVar) {
        this.b.remove(aVar);
    }

    public TaskExecutor() {
        this(new a());
    }

    public boolean execute(Runnable runnable, long j) {
        return execute(runnable, j, 0L);
    }

    public boolean execute(Runnable runnable, long j, long j2) {
        return execute(runnable, j, j2, false);
    }

    public boolean execute(Runnable runnable, long j, long j2, boolean z) {
        if (!this.c) {
            return false;
        }
        for (com.comscore.android.task.a aVar : this.b) {
            if (aVar != null && aVar.f() == runnable) {
                return false;
            }
        }
        this.b.add(new com.comscore.android.task.a(runnable, j, j2, z));
        this.a.a();
        return true;
    }
}
