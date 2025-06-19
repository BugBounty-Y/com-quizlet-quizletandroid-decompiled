package io.reactivex.rxjava3.subjects;

import androidx.appcompat.widget.C0122z;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.functions.i {
    public final io.reactivex.rxjava3.core.l a;
    public final d b;
    public boolean c;
    public boolean d;
    public C0122z e;
    public boolean f;
    public volatile boolean g;
    public long h;

    public c(io.reactivex.rxjava3.core.l lVar, d dVar) {
        this.a = lVar;
        this.b = dVar;
    }

    public final void a(long j, Object obj) {
        if (this.g) {
            return;
        }
        if (!this.f) {
            synchronized (this) {
                try {
                    if (this.g) {
                        return;
                    }
                    if (this.h == j) {
                        return;
                    }
                    if (this.d) {
                        C0122z c0122z = this.e;
                        if (c0122z == null) {
                            c0122z = new C0122z(21, (byte) 0);
                            this.e = c0122z;
                        }
                        c0122z.b(obj);
                        return;
                    }
                    this.c = true;
                    this.f = true;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        test(obj);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.g) {
            return;
        }
        this.g = true;
        this.b.A(this);
    }

    @Override // io.reactivex.rxjava3.functions.i
    public final boolean test(Object obj) {
        if (this.g) {
            return true;
        }
        io.reactivex.rxjava3.core.l lVar = this.a;
        if (obj == io.reactivex.rxjava3.internal.util.e.a) {
            lVar.onComplete();
            return true;
        }
        if (obj instanceof io.reactivex.rxjava3.internal.util.d) {
            lVar.onError(((io.reactivex.rxjava3.internal.util.d) obj).a);
            return true;
        }
        lVar.b(obj);
        return false;
    }
}
