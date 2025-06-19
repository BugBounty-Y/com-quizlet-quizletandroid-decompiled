package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.core.q, io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.h b;
    public final io.reactivex.rxjava3.functions.i c;
    public io.reactivex.rxjava3.disposables.b d;

    public /* synthetic */ g(io.reactivex.rxjava3.core.h hVar, io.reactivex.rxjava3.functions.i iVar, int i) {
        this.a = i;
        this.b = hVar;
        this.c = iVar;
    }

    @Override // io.reactivex.rxjava3.core.q
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

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.d;
                this.d = io.reactivex.rxjava3.internal.disposables.a.a;
                bVar.dispose();
                break;
            default:
                this.d.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        this.b.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.b.onError(th);
                break;
            default:
                io.reactivex.rxjava3.core.h hVar = this.b;
                try {
                    if (!this.c.test(th)) {
                        hVar.onError(th);
                        break;
                    } else {
                        hVar.onComplete();
                        break;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    hVar.onError(new CompositeException(th, th2));
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.core.h hVar = this.b;
                try {
                    if (!this.c.test(obj)) {
                        hVar.onComplete();
                        break;
                    } else {
                        hVar.onSuccess(obj);
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    hVar.onError(th);
                    return;
                }
            default:
                this.b.onSuccess(obj);
                break;
        }
    }
}
