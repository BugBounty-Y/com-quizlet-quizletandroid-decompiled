package io.reactivex.rxjava3.internal.operators.single;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class f extends AtomicReference implements io.reactivex.rxjava3.core.q, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.q b;
    public final io.reactivex.rxjava3.functions.h c;

    public /* synthetic */ f(int i, io.reactivex.rxjava3.core.q qVar, io.reactivex.rxjava3.functions.h hVar) {
        this.a = i;
        this.b = qVar;
        this.c = hVar;
    }

    @Override // io.reactivex.rxjava3.core.q
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

    @Override // io.reactivex.rxjava3.core.q
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                this.b.onError(th);
                break;
            default:
                io.reactivex.rxjava3.core.q qVar = this.b;
                try {
                    Object objApply = this.c.apply(th);
                    Objects.requireNonNull(objApply, "The nextFunction returned a null SingleSource.");
                    ((io.reactivex.rxjava3.core.p) objApply).j(new com.quizlet.remote.model.progress.e(this, qVar));
                    break;
                } catch (Throwable th2) {
                    x7.b(th2);
                    qVar.onError(new CompositeException(th, th2));
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.core.q qVar = this.b;
                try {
                    Object objApply = this.c.apply(obj);
                    Objects.requireNonNull(objApply, "The single returned by the mapper is null");
                    io.reactivex.rxjava3.core.p pVar = (io.reactivex.rxjava3.core.p) objApply;
                    if (!io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get())) {
                        pVar.j(new com.quizlet.remote.model.user.delete.c(this, qVar));
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    qVar.onError(th);
                    return;
                }
                break;
            default:
                this.b.onSuccess(obj);
                break;
        }
    }
}
