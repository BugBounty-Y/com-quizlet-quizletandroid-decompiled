package com.bumptech.glide.request;

/* loaded from: classes.dex */
public final class b implements d, c {
    public final Object a;
    public final Object b;
    public volatile c c;
    public volatile c d;
    public int e = 3;
    public int f = 3;

    public b(Object obj, d dVar) {
        this.a = obj;
        this.b = dVar;
    }

    @Override // com.bumptech.glide.request.d, com.bumptech.glide.request.c
    public final boolean a() {
        boolean z;
        synchronized (this.a) {
            try {
                z = this.c.a() || this.d.a();
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r3v3, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final void b(c cVar) {
        synchronized (this.a) {
            try {
                if (cVar.equals(this.d)) {
                    this.f = 5;
                    ?? r3 = this.b;
                    if (r3 != 0) {
                        r3.b(this);
                    }
                    return;
                }
                this.e = 5;
                if (this.f != 1) {
                    this.f = 1;
                    this.d.g();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean c(c cVar) {
        if (cVar instanceof b) {
            b bVar = (b) cVar;
            if (this.c.c(bVar.c) && this.d.c(bVar.d)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.request.c
    public final void clear() {
        synchronized (this.a) {
            try {
                this.e = 3;
                this.c.clear();
                if (this.f != 3) {
                    this.f = 3;
                    this.d.clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean d() {
        boolean z;
        synchronized (this.a) {
            try {
                z = this.e == 3 && this.f == 3;
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean e(c cVar) {
        boolean z;
        int i;
        synchronized (this.a) {
            ?? r1 = this.b;
            z = false;
            if (r1 == 0 || r1.e(this)) {
                if (this.e != 5 ? cVar.equals(this.c) : cVar.equals(this.d) && ((i = this.f) == 4 || i == 5)) {
                    z = true;
                }
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean f(c cVar) {
        boolean z;
        synchronized (this.a) {
            ?? r0 = this.b;
            z = r0 == 0 || r0.f(this);
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final void g() {
        synchronized (this.a) {
            try {
                if (this.e != 1) {
                    this.e = 1;
                    this.c.g();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final d getRoot() {
        d root;
        synchronized (this.a) {
            try {
                ?? r1 = this.b;
                root = r1 != 0 ? r1.getRoot() : this;
            } catch (Throwable th) {
                throw th;
            }
        }
        return root;
    }

    /* JADX WARN: Type inference failed for: r4v3, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final void h(c cVar) {
        synchronized (this.a) {
            try {
                if (cVar.equals(this.c)) {
                    this.e = 4;
                } else if (cVar.equals(this.d)) {
                    this.f = 4;
                }
                ?? r4 = this.b;
                if (r4 != 0) {
                    r4.h(this);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean i() {
        boolean z;
        synchronized (this.a) {
            try {
                z = this.e == 4 || this.f == 4;
            } finally {
            }
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final boolean isRunning() {
        boolean z;
        synchronized (this.a) {
            try {
                z = true;
                if (this.e != 1 && this.f != 1) {
                    z = false;
                }
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean j(c cVar) {
        boolean z;
        synchronized (this.a) {
            ?? r1 = this.b;
            z = (r1 == 0 || r1.j(this)) && cVar.equals(this.c);
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final void pause() {
        synchronized (this.a) {
            try {
                if (this.e == 1) {
                    this.e = 2;
                    this.c.pause();
                }
                if (this.f == 1) {
                    this.f = 2;
                    this.d.pause();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
