package io.reactivex.rxjava3.internal.observers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.core.q;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class g implements l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public io.reactivex.rxjava3.disposables.b b;
    public final Object c;
    public final Object d;
    public Object e;

    public /* synthetic */ g(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                l lVar = (l) this.c;
                try {
                    ((io.reactivex.rxjava3.functions.d) this.d).accept(bVar);
                    if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                        this.b = bVar;
                        lVar.a(this);
                        break;
                    }
                } catch (Throwable th) {
                    x7.b(th);
                    bVar.dispose();
                    this.b = io.reactivex.rxjava3.internal.disposables.a.a;
                    io.reactivex.rxjava3.internal.disposables.b.d(th, lVar);
                    return;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((q) this.c).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                ((l) this.c).b(obj);
                break;
            default:
                Object obj2 = this.e;
                if (obj2 != null) {
                    try {
                        Object objApply = ((io.reactivex.rxjava3.functions.b) this.d).apply(obj2, obj);
                        Objects.requireNonNull(objApply, "The reducer returned a null value");
                        this.e = objApply;
                        break;
                    } catch (Throwable th) {
                        x7.b(th);
                        this.b.dispose();
                        onError(th);
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.b;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar) {
                    this.b = aVar;
                    try {
                        ((io.reactivex.rxjava3.functions.a) this.e).run();
                    } catch (Throwable th) {
                        x7.b(th);
                        C7.c(th);
                    }
                    bVar.dispose();
                    break;
                }
                break;
            default:
                this.b.dispose();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.b;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar != aVar) {
                    this.b = aVar;
                    ((l) this.c).onComplete();
                    break;
                }
                break;
            default:
                Object obj = this.e;
                if (obj != null) {
                    this.e = null;
                    ((q) this.c).onSuccess(obj);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                io.reactivex.rxjava3.disposables.b bVar = this.b;
                io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                if (bVar == aVar) {
                    C7.c(th);
                    break;
                } else {
                    this.b = aVar;
                    ((l) this.c).onError(th);
                    break;
                }
            default:
                if (this.e == null) {
                    C7.c(th);
                    break;
                } else {
                    this.e = null;
                    ((q) this.c).onError(th);
                    break;
                }
        }
    }
}
