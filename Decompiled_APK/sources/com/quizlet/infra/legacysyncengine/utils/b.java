package com.quizlet.infra.legacysyncengine.utils;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.subjects.s;
import retrofit2.K;
import retrofit2.adapter.rxjava3.d;

/* loaded from: classes3.dex */
public class b implements l {
    public final /* synthetic */ int a;
    public final l b;

    public /* synthetic */ b(l lVar, int i) {
        this.a = i;
        this.b = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                ((s) this.b).a(bVar);
                break;
            default:
                this.b.a(bVar);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        switch (this.a) {
            case 0:
                ((s) this.b).b(obj);
                return;
            default:
                if (((K) obj) == null) {
                    throw new NullPointerException("response == null");
                }
                this.b.b(new d(0));
                return;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        switch (this.a) {
            case 0:
                ((s) this.b).onComplete();
                break;
            default:
                this.b.onComplete();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public void onError(Throwable th) {
        switch (this.a) {
            case 0:
                ((s) this.b).onError(th);
                return;
            default:
                l lVar = this.b;
                try {
                    if (th == null) {
                        throw new NullPointerException("error == null");
                    }
                    lVar.b(new d(0));
                    lVar.onComplete();
                    return;
                } catch (Throwable th2) {
                    try {
                        lVar.onError(th2);
                        return;
                    } catch (Throwable th3) {
                        x7.b(th3);
                        C7.c(new CompositeException(th2, th3));
                        return;
                    }
                }
        }
    }
}
