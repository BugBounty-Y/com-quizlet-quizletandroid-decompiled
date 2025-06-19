package com.bumptech.glide.load.engine;

/* loaded from: classes.dex */
public final class q implements v {
    public final boolean a;
    public final boolean b;
    public final v c;
    public final l d;
    public final p e;
    public int f;
    public boolean g;

    public q(v vVar, boolean z, boolean z2, p pVar, l lVar) {
        com.bumptech.glide.util.f.c(vVar, "Argument must not be null");
        this.c = vVar;
        this.a = z;
        this.b = z2;
        this.e = pVar;
        com.bumptech.glide.util.f.c(lVar, "Argument must not be null");
        this.d = lVar;
    }

    @Override // com.bumptech.glide.load.engine.v
    public final int a() {
        return this.c.a();
    }

    public final synchronized void b() {
        if (this.g) {
            throw new IllegalStateException("Cannot acquire a recycled resource");
        }
        this.f++;
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Class c() {
        return this.c.c();
    }

    public final void d() {
        boolean z;
        synchronized (this) {
            int i = this.f;
            if (i <= 0) {
                throw new IllegalStateException("Cannot release a recycled or not yet acquired resource");
            }
            z = true;
            int i2 = i - 1;
            this.f = i2;
            if (i2 != 0) {
                z = false;
            }
        }
        if (z) {
            this.d.d(this.e, this);
        }
    }

    @Override // com.bumptech.glide.load.engine.v
    public final Object get() {
        return this.c.get();
    }

    @Override // com.bumptech.glide.load.engine.v
    public final synchronized void recycle() {
        if (this.f > 0) {
            throw new IllegalStateException("Cannot recycle a resource while it is still acquired");
        }
        if (this.g) {
            throw new IllegalStateException("Cannot recycle a resource that has already been recycled");
        }
        this.g = true;
        if (this.b) {
            this.c.recycle();
        }
    }

    public final synchronized String toString() {
        return "EngineResource{isMemoryCacheable=" + this.a + ", listener=" + this.d + ", key=" + this.e + ", acquired=" + this.f + ", isRecycled=" + this.g + ", resource=" + this.c + '}';
    }
}
