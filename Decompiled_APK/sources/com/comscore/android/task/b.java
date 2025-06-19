package com.comscore.android.task;

/* loaded from: classes.dex */
class b extends Thread {
    private boolean a = false;
    private Object b = new Object();
    private TaskExecutor c;
    private TaskExceptionHandler d;

    public b(TaskExecutor taskExecutor, TaskExceptionHandler taskExceptionHandler) {
        this.d = taskExceptionHandler;
        this.c = taskExecutor;
    }

    public void a() {
        synchronized (this.b) {
            this.b.notify();
        }
    }

    public void b() {
        this.a = true;
    }

    public boolean c() {
        return this.a;
    }

    public void d() {
        long jB = this.c.b();
        if (jB > 0) {
            a(jB);
        }
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        TaskExceptionHandler taskExceptionHandler;
        while (!c()) {
            a aVarA = this.c.a();
            if (aVarA != null) {
                aVarA.run();
                if (aVarA.b() != null && (taskExceptionHandler = this.d) != null) {
                    taskExceptionHandler.exception(aVarA.b(), this.c, aVarA.f());
                }
                this.c.a(aVarA);
                if (aVarA.j()) {
                    this.c.execute(aVarA.f(), aVarA.e(), aVarA.e());
                }
            } else {
                d();
            }
        }
    }

    private void a(long j) {
        synchronized (this.b) {
            try {
                this.b.wait(j);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
