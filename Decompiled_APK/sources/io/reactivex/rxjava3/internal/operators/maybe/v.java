package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;

/* loaded from: classes3.dex */
public final class v extends io.reactivex.rxjava3.internal.observers.f implements io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int c;
    public io.reactivex.rxjava3.disposables.b d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ v(io.reactivex.rxjava3.core.l lVar, int i) {
        super(lVar);
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.c) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    this.a.a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    this.a.a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.c) {
            case 0:
                set(4);
                this.b = null;
                this.d.dispose();
                break;
            default:
                set(4);
                this.b = null;
                this.d.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        if ((get() & 54) != 0) {
            return;
        }
        lazySet(2);
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        switch (this.c) {
            case 0:
                if ((get() & 54) == 0) {
                    lazySet(2);
                    this.a.onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            default:
                if ((get() & 54) == 0) {
                    lazySet(2);
                    this.a.onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
        }
    }
}
