package retrofit2.adapter.rxjava3;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.exceptions.CompositeException;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a implements l {
    public final l a;
    public boolean b;

    public a(l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.a.a(bVar);
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        K k = (K) obj;
        boolean zD = k.a.d();
        l lVar = this.a;
        if (zD) {
            lVar.b(k.b);
            return;
        }
        this.b = true;
        HttpException httpException = new HttpException(k);
        try {
            lVar.onError(httpException);
        } catch (Throwable th) {
            x7.b(th);
            C7.c(new CompositeException(httpException, th));
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.b) {
            return;
        }
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (!this.b) {
            this.a.onError(th);
            return;
        }
        AssertionError assertionError = new AssertionError("This should never happen! Report as a bug with the full stacktrace.");
        assertionError.initCause(th);
        C7.c(assertionError);
    }
}
