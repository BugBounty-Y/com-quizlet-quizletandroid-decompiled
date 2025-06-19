package io.reactivex.rxjava3.disposables;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.exceptions.OnErrorNotImplementedException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class d extends AtomicReference implements b, io.reactivex.rxjava3.core.b {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.e(this, bVar);
    }

    public boolean b() {
        switch (this.a) {
            case 0:
                return get() == null;
            default:
                return io.reactivex.rxjava3.internal.disposables.a.b((b) get());
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        Object andSet;
        io.reactivex.rxjava3.functions.c cVar;
        switch (this.a) {
            case 0:
                if (get() != null && (andSet = getAndSet(null)) != null) {
                    ((Runnable) andSet).run();
                    break;
                }
                break;
            case 1:
                if (get() != null && (cVar = (io.reactivex.rxjava3.functions.c) getAndSet(null)) != null) {
                    try {
                        cVar.cancel();
                        break;
                    } catch (Throwable th) {
                        x7.b(th);
                        C7.c(th);
                        return;
                    }
                }
                break;
            case 2:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.a.a(this);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        lazySet(io.reactivex.rxjava3.internal.disposables.a.a);
        C7.c(new OnErrorNotImplementedException(th));
    }

    @Override // java.util.concurrent.atomic.AtomicReference
    public String toString() {
        switch (this.a) {
            case 0:
                return "RunnableDisposable(disposed=" + b() + ", " + get() + ")";
            default:
                return super.toString();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(Object obj, int i) {
        super(obj);
        this.a = i;
    }
}
