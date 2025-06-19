package com.bumptech.glide.request;

/* loaded from: classes.dex */
public final class h implements d, c {
    public final Object a;
    public final Object b;
    public volatile g c;
    public volatile c d;
    public int e = 3;
    public int f = 3;
    public boolean g;

    public h(Object obj, d dVar) {
        this.b = obj;
        this.a = dVar;
    }

    @Override // com.bumptech.glide.request.d, com.bumptech.glide.request.c
    public final boolean a() {
        boolean z;
        synchronized (this.b) {
            try {
                z = this.d.a() || this.c.a();
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r3v3, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final void b(c cVar) {
        synchronized (this.b) {
            try {
                if (!cVar.equals(this.c)) {
                    this.f = 5;
                    return;
                }
                this.e = 5;
                ?? r3 = this.a;
                if (r3 != 0) {
                    r3.b(this);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean c(c cVar) {
        if (!(cVar instanceof h)) {
            return false;
        }
        h hVar = (h) cVar;
        if (this.c == null) {
            if (hVar.c != null) {
                return false;
            }
        } else if (!this.c.c(hVar.c)) {
            return false;
        }
        return this.d == null ? hVar.d == null : this.d.c(hVar.d);
    }

    @Override // com.bumptech.glide.request.c
    public final void clear() {
        synchronized (this.b) {
            this.g = false;
            this.e = 3;
            this.f = 3;
            this.d.clear();
            this.c.clear();
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean d() {
        boolean z;
        synchronized (this.b) {
            z = this.e == 3;
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean e(c cVar) {
        boolean z;
        synchronized (this.b) {
            try {
                ?? r1 = this.a;
                z = (r1 == 0 || r1.e(this)) && cVar.equals(this.c) && !a();
            } finally {
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean f(c cVar) {
        boolean z;
        synchronized (this.b) {
            try {
                ?? r1 = this.a;
                z = (r1 == 0 || r1.f(this)) && (cVar.equals(this.c) || this.e != 4);
            } finally {
            }
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final void g() {
        synchronized (this.b) {
            try {
                this.g = true;
                try {
                    if (this.e != 4 && this.f != 1) {
                        this.f = 1;
                        this.d.g();
                    }
                    if (this.g && this.e != 1) {
                        this.e = 1;
                        this.c.g();
                    }
                    this.g = false;
                } catch (Throwable th) {
                    this.g = false;
                    throw th;
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final d getRoot() {
        d root;
        synchronized (this.b) {
            try {
                ?? r1 = this.a;
                root = r1 != 0 ? r1.getRoot() : this;
            } catch (Throwable th) {
                throw th;
            }
        }
        return root;
    }

    /* JADX WARN: Type inference failed for: r3v3, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final void h(c cVar) {
        synchronized (this.b) {
            try {
                if (cVar.equals(this.d)) {
                    this.f = 4;
                    return;
                }
                this.e = 4;
                ?? r3 = this.a;
                if (r3 != 0) {
                    r3.h(this);
                }
                if (!assistantMode.refactored.a.b(this.f)) {
                    this.d.clear();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.bumptech.glide.request.c
    public final boolean i() {
        boolean z;
        synchronized (this.b) {
            z = this.e == 4;
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final boolean isRunning() {
        boolean z;
        synchronized (this.b) {
            z = true;
            if (this.e != 1) {
                z = false;
            }
        }
        return z;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.bumptech.glide.request.d, java.lang.Object] */
    @Override // com.bumptech.glide.request.d
    public final boolean j(c cVar) {
        boolean z;
        synchronized (this.b) {
            try {
                ?? r1 = this.a;
                z = (r1 == 0 || r1.j(this)) && cVar.equals(this.c) && this.e != 2;
            } finally {
            }
        }
        return z;
    }

    @Override // com.bumptech.glide.request.c
    public final void pause() {
        synchronized (this.b) {
            try {
                if (!assistantMode.refactored.a.b(this.f)) {
                    this.f = 2;
                    this.d.pause();
                }
                if (!assistantMode.refactored.a.b(this.e)) {
                    this.e = 2;
                    this.c.pause();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
