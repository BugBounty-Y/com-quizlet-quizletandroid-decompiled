package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class h extends io.reactivex.rxjava3.internal.observers.b implements io.reactivex.rxjava3.core.q {
    public final io.reactivex.rxjava3.core.l a;
    public final com.quizlet.quizletandroid.ui.usersettings.b b;
    public io.reactivex.rxjava3.disposables.b c;
    public volatile Iterator d;
    public volatile boolean e;
    public boolean f;

    public h(io.reactivex.rxjava3.core.l lVar, com.quizlet.quizletandroid.ui.usersettings.b bVar) {
        this.a = lVar;
        this.b = bVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
            this.c = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.d = null;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e = true;
        this.c.dispose();
        this.c = io.reactivex.rxjava3.internal.disposables.a.a;
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        this.f = true;
        return 2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.d == null;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        this.c = io.reactivex.rxjava3.internal.disposables.a.a;
        this.a.onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        io.reactivex.rxjava3.core.l lVar = this.a;
        try {
            Iterator it2 = ((Iterable) this.b.apply(obj)).iterator();
            if (!it2.hasNext()) {
                lVar.onComplete();
                return;
            }
            if (this.f) {
                this.d = it2;
                lVar.b(null);
                lVar.onComplete();
                return;
            }
            while (!this.e) {
                try {
                    lVar.b(it2.next());
                    if (this.e) {
                        return;
                    }
                    try {
                        if (!it2.hasNext()) {
                            lVar.onComplete();
                            return;
                        }
                    } catch (Throwable th) {
                        x7.b(th);
                        lVar.onError(th);
                        return;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    lVar.onError(th2);
                    return;
                }
            }
        } catch (Throwable th3) {
            x7.b(th3);
            this.a.onError(th3);
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        Iterator it2 = this.d;
        if (it2 == null) {
            return null;
        }
        Object next = it2.next();
        Objects.requireNonNull(next, "The iterator returned a null value");
        if (!it2.hasNext()) {
            this.d = null;
        }
        return next;
    }
}
