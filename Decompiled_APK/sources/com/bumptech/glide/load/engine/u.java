package com.bumptech.glide.load.engine;

/* loaded from: classes.dex */
public final class u implements v, com.bumptech.glide.util.pool.b {
    public static final com.quizlet.data.repository.course.membership.c e = com.bumptech.glide.util.pool.d.a(20, new com.google.firebase.perf.logging.b(6));
    public final com.bumptech.glide.util.pool.e a = new com.bumptech.glide.util.pool.e();
    public v b;
    public boolean c;
    public boolean d;

    @Override // com.bumptech.glide.load.engine.v
    public final int a() {
        return this.b.a();
    }

    @Override // com.bumptech.glide.util.pool.b
    public final com.bumptech.glide.util.pool.e b() {
        return this.a;
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Class c() {
        return this.b.c();
    }

    public final synchronized void d() {
        this.a.a();
        if (!this.c) {
            throw new IllegalStateException("Already unlocked");
        }
        this.c = false;
        if (this.d) {
            recycle();
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Object get() {
        return this.b.get();
    }

    @Override // com.bumptech.glide.load.engine.v
    public final synchronized void recycle() {
        this.a.a();
        this.d = true;
        if (!this.c) {
            this.b.recycle();
            this.b = null;
            e.o(this);
        }
    }
}
