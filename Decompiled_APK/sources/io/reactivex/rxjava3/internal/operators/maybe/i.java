package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class i extends AtomicReference implements io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.disposables.b, io.reactivex.rxjava3.core.q {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.h b;
    public final io.reactivex.rxjava3.functions.h c;

    public /* synthetic */ i(io.reactivex.rxjava3.core.h hVar, io.reactivex.rxjava3.functions.h hVar2, int i) {
        this.a = i;
        this.b = hVar;
        this.c = hVar2;
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    this.b.a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
                    this.b.a(this);
                    break;
                }
                break;
        }
    }

    public final boolean b() {
        switch (this.a) {
        }
        return io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get());
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h
    public void onComplete() {
        this.b.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.b.onError(th);
                break;
            default:
                this.b.onError(th);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                try {
                    Object objApply = this.c.apply(obj);
                    Objects.requireNonNull(objApply, "The mapper returned a null SingleSource");
                    io.reactivex.rxjava3.core.p pVar = (io.reactivex.rxjava3.core.p) objApply;
                    if (!b()) {
                        pVar.j(new com.quizlet.remote.model.search.d(this, this.b));
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    onError(th);
                    return;
                }
                break;
            default:
                try {
                    Object objApply2 = this.c.apply(obj);
                    Objects.requireNonNull(objApply2, "The mapper returned a null MaybeSource");
                    io.reactivex.rxjava3.core.g gVar = (io.reactivex.rxjava3.core.g) objApply2;
                    if (!b()) {
                        gVar.e(new io.reactivex.rxjava3.internal.operators.single.i(this, this.b));
                        break;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    onError(th2);
                }
                break;
        }
    }
}
