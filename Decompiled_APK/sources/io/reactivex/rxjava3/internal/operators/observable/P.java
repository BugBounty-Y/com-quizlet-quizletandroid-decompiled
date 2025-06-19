package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class P implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.l b;
    public final io.reactivex.rxjava3.functions.h c;
    public io.reactivex.rxjava3.disposables.b d;

    public /* synthetic */ P(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar, int i) {
        this.a = i;
        this.b = lVar;
        this.c = hVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    this.b.a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    this.b.a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                if (this.d != io.reactivex.rxjava3.internal.disposables.a.a) {
                    try {
                        for (Object obj2 : (Iterable) this.c.apply(obj)) {
                            try {
                                try {
                                    Objects.requireNonNull(obj2, "The iterator returned a null value");
                                    this.b.b(obj2);
                                } catch (Throwable th) {
                                    x7.b(th);
                                    this.d.dispose();
                                    onError(th);
                                    return;
                                }
                            } catch (Throwable th2) {
                                x7.b(th2);
                                this.d.dispose();
                                onError(th2);
                                return;
                            }
                        }
                        break;
                    } catch (Throwable th3) {
                        x7.b(th3);
                        this.d.dispose();
                        onError(th3);
                        return;
                    }
                }
                break;
            default:
                this.b.b(obj);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.d.dispose();
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                break;
            default:
                this.d.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.d;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar) {
                    this.d = aVar;
                    this.b.onComplete();
                    break;
                }
                break;
            default:
                this.b.onComplete();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.d;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar) {
                    this.d = aVar;
                    this.b.onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            default:
                io.reactivex.rxjava3.core.l lVar = this.b;
                try {
                    Object objApply = this.c.apply(th);
                    if (objApply != null) {
                        lVar.b(objApply);
                        lVar.onComplete();
                        break;
                    } else {
                        NullPointerException nullPointerException = new NullPointerException("The supplied value is null");
                        nullPointerException.initCause(th);
                        lVar.onError(nullPointerException);
                        break;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    lVar.onError(new CompositeException(th, th2));
                }
        }
    }
}
