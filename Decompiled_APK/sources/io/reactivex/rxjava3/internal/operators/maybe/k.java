package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements io.reactivex.rxjava3.core.q, io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.h {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.h b;
    public io.reactivex.rxjava3.disposables.b c;

    public /* synthetic */ k(io.reactivex.rxjava3.core.h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
                    this.b.a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
                    this.c = bVar;
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
                this.c.dispose();
                this.c = io.reactivex.rxjava3.internal.disposables.a.a;
                break;
            default:
                this.c.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        this.b.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable it2) {
        switch (this.a) {
            case 0:
                this.c = io.reactivex.rxjava3.internal.disposables.a.a;
                this.b.onError(it2);
                break;
            default:
                io.reactivex.rxjava3.core.h hVar = this.b;
                try {
                    Intrinsics.checkNotNullParameter(it2, "it");
                    timber.log.c.a.e(it2);
                    hVar.onSuccess(Boolean.FALSE);
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    hVar.onError(new CompositeException(it2, th));
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                this.c = io.reactivex.rxjava3.internal.disposables.a.a;
                this.b.onSuccess(obj);
                break;
            default:
                this.b.onSuccess(obj);
                break;
        }
    }
}
