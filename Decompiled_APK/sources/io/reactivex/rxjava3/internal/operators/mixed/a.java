package io.reactivex.rxjava3.internal.operators.mixed;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.k;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.functions.h;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class a extends AtomicReference implements l, io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b, q {
    public final /* synthetic */ int a;
    public final l b;
    public Object c;

    public /* synthetic */ a(l lVar, Object obj, int i) {
        this.a = i;
        this.c = obj;
        this.b = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.c(this, bVar);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.e((AtomicReference) this.c, bVar);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                this.b.b(obj);
                break;
            case 1:
                this.b.b(obj);
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
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            case 1:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a((AtomicReference) this.c);
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                i iVar = (i) this.c;
                if (iVar != null) {
                    this.c = null;
                    iVar.c(this);
                    break;
                } else {
                    this.b.onComplete();
                    break;
                }
            case 1:
                this.b.onComplete();
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
                this.b.onError(th);
                break;
            case 1:
                this.b.onError(th);
                break;
            default:
                this.b.onError(th);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        try {
            Object objApply = ((h) this.c).apply(obj);
            Objects.requireNonNull(objApply, "The mapper returned a null Publisher");
            k kVar = (k) objApply;
            if (io.reactivex.rxjava3.internal.disposables.a.b((io.reactivex.rxjava3.disposables.b) get())) {
                return;
            }
            kVar.c(this);
        } catch (Throwable th) {
            x7.b(th);
            this.b.onError(th);
        }
    }

    public a(l lVar) {
        this.a = 2;
        this.b = lVar;
        this.c = new AtomicReference();
    }
}
