package com.comscore.android.task;

import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
class a implements Runnable {
    private AtomicBoolean a;
    private AtomicBoolean b;
    private Runnable c;
    private long d;
    private long e;
    private long f;
    private boolean g;
    private boolean h;
    private Exception i;

    public a(Runnable runnable) {
        this(runnable, 0L);
    }

    public long a() {
        return this.e;
    }

    public Exception b() {
        return this.i;
    }

    public long c() {
        return this.d;
    }

    public long d() {
        long jCurrentTimeMillis = this.d - System.currentTimeMillis();
        if (jCurrentTimeMillis > 0) {
            return jCurrentTimeMillis;
        }
        return 0L;
    }

    public long e() {
        return this.f;
    }

    public Runnable f() {
        return this.c;
    }

    public boolean g() {
        return this.h;
    }

    public boolean h() {
        return this.g;
    }

    public boolean i() {
        return this.b.get();
    }

    public boolean j() {
        return this.f > 0;
    }

    public boolean k() {
        return this.a.get();
    }

    @Override // java.lang.Runnable
    public void run() {
        this.a.set(true);
        try {
            this.c.run();
        } catch (Exception e) {
            this.i = e;
        }
        this.a.set(false);
        this.b.set(true);
    }

    public a(Runnable runnable, long j) {
        this(runnable, j, 0L);
    }

    public a(Runnable runnable, long j, long j2) {
        this(runnable, j, j2, true);
    }

    public a(Runnable runnable, long j, long j2, boolean z) {
        this.c = runnable;
        this.d = System.currentTimeMillis() + (j <= 0 ? 0L : j);
        this.g = j > 0;
        this.e = System.currentTimeMillis();
        this.f = j2;
        this.a = new AtomicBoolean();
        AtomicBoolean atomicBoolean = new AtomicBoolean();
        this.b = atomicBoolean;
        atomicBoolean.set(false);
        this.a.set(false);
        this.i = null;
        this.h = z;
    }
}
