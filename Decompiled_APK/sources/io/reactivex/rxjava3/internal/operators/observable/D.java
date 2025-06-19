package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class D implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public final kotlin.collections.K b;
    public io.reactivex.rxjava3.disposables.b c;
    public long d;
    public boolean e;
    public final Object f;

    public /* synthetic */ D(Object obj, kotlin.collections.K k, int i) {
        this.a = i;
        this.f = obj;
        this.b = k;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.l) this.f).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    ((io.reactivex.rxjava3.core.q) this.f).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                if (!this.e) {
                    long j = this.d;
                    if (j != 0) {
                        this.d = j + 1;
                        break;
                    } else {
                        this.e = true;
                        this.c.dispose();
                        io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.f;
                        lVar.b(obj);
                        lVar.onComplete();
                        break;
                    }
                }
                break;
            default:
                if (!this.e) {
                    long j2 = this.d;
                    if (j2 != 0) {
                        this.d = j2 + 1;
                        break;
                    } else {
                        this.e = true;
                        this.c.dispose();
                        ((io.reactivex.rxjava3.core.q) this.f).onSuccess(obj);
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
            default:
                this.c.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                if (!this.e) {
                    this.e = true;
                    io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.f;
                    kotlin.collections.K k = this.b;
                    if (k != null) {
                        if (k != null) {
                            lVar.b(k);
                        }
                        lVar.onComplete();
                        break;
                    } else {
                        lVar.onError(new NoSuchElementException());
                        break;
                    }
                }
                break;
            default:
                if (!this.e) {
                    this.e = true;
                    io.reactivex.rxjava3.core.q qVar = (io.reactivex.rxjava3.core.q) this.f;
                    kotlin.collections.K k2 = this.b;
                    if (k2 == null) {
                        qVar.onError(new NoSuchElementException());
                        break;
                    } else {
                        qVar.onSuccess(k2);
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
                if (!this.e) {
                    this.e = true;
                    ((io.reactivex.rxjava3.core.l) this.f).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            default:
                if (!this.e) {
                    this.e = true;
                    ((io.reactivex.rxjava3.core.q) this.f).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
        }
    }
}
