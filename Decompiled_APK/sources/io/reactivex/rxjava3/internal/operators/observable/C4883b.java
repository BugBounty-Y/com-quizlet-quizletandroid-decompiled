package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.NoSuchElementException;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4883b implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public Object b;
    public io.reactivex.rxjava3.disposables.b c;
    public boolean d;
    public final Object e;

    public /* synthetic */ C4883b(Object obj, int i) {
        this.a = i;
        this.e = obj;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.l) this.e).a(this);
                    break;
                }
                break;
            case 1:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.q) this.e).a(this);
                    break;
                }
                break;
            case 2:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.h) this.e).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.q) this.e).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                if (!this.d) {
                    try {
                        if (!((io.reactivex.rxjava3.functions.i) this.b).test(obj)) {
                            this.d = true;
                            this.c.dispose();
                            Boolean bool = Boolean.FALSE;
                            io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.e;
                            lVar.b(bool);
                            lVar.onComplete();
                            break;
                        }
                    } catch (Throwable th) {
                        x7.b(th);
                        this.c.dispose();
                        onError(th);
                        return;
                    }
                }
                break;
            case 1:
                if (!this.d) {
                    try {
                        if (!((io.reactivex.rxjava3.functions.i) this.b).test(obj)) {
                            this.d = true;
                            this.c.dispose();
                            ((io.reactivex.rxjava3.core.q) this.e).onSuccess(Boolean.FALSE);
                            break;
                        }
                    } catch (Throwable th2) {
                        x7.b(th2);
                        this.c.dispose();
                        onError(th2);
                        return;
                    }
                }
                break;
            case 2:
                if (!this.d) {
                    if (this.b == null) {
                        this.b = obj;
                        break;
                    } else {
                        this.d = true;
                        this.c.dispose();
                        ((io.reactivex.rxjava3.core.h) this.e).onError(new IllegalArgumentException("Sequence contains more than one element!"));
                        break;
                    }
                }
                break;
            default:
                if (!this.d) {
                    if (this.b == null) {
                        this.b = obj;
                        break;
                    } else {
                        this.d = true;
                        this.c.dispose();
                        ((io.reactivex.rxjava3.core.q) this.e).onError(new IllegalArgumentException("Sequence contains more than one element!"));
                        break;
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.c.dispose();
                break;
            case 1:
                this.c.dispose();
                break;
            case 2:
                this.c.dispose();
                break;
            default:
                this.c.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                if (!this.d) {
                    this.d = true;
                    Boolean bool = Boolean.TRUE;
                    io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.e;
                    lVar.b(bool);
                    lVar.onComplete();
                    break;
                }
                break;
            case 1:
                if (!this.d) {
                    this.d = true;
                    ((io.reactivex.rxjava3.core.q) this.e).onSuccess(Boolean.TRUE);
                    break;
                }
                break;
            case 2:
                if (!this.d) {
                    this.d = true;
                    Object obj = this.b;
                    this.b = null;
                    io.reactivex.rxjava3.core.h hVar = (io.reactivex.rxjava3.core.h) this.e;
                    if (obj != null) {
                        hVar.onSuccess(obj);
                        break;
                    } else {
                        hVar.onComplete();
                        break;
                    }
                }
                break;
            default:
                if (!this.d) {
                    this.d = true;
                    Object obj2 = this.b;
                    this.b = null;
                    if (obj2 == null) {
                        obj2 = null;
                    }
                    io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.e;
                    if (obj2 == null) {
                        qVar.onError(new NoSuchElementException());
                        break;
                    } else {
                        qVar.onSuccess(obj2);
                        break;
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                if (!this.d) {
                    this.d = true;
                    ((io.reactivex.rxjava3.core.l) this.e).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            case 1:
                if (!this.d) {
                    this.d = true;
                    ((io.reactivex.rxjava3.core.q) this.e).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            case 2:
                if (!this.d) {
                    this.d = true;
                    ((io.reactivex.rxjava3.core.h) this.e).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            default:
                if (!this.d) {
                    this.d = true;
                    ((io.reactivex.rxjava3.core.q) this.e).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
        }
    }

    public /* synthetic */ C4883b(Object obj, io.reactivex.rxjava3.functions.i iVar, int i) {
        this.a = i;
        this.e = obj;
        this.b = iVar;
    }
}
