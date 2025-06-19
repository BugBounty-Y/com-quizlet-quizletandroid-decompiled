package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4886e implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final /* synthetic */ int a;
    public io.reactivex.rxjava3.disposables.b b;
    public boolean c;
    public final Object d;

    public /* synthetic */ C4886e(Object obj, int i) {
        this.a = i;
        this.d = obj;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((io.reactivex.rxjava3.core.l) this.d).a(this);
                    break;
                }
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
                    this.b = bVar;
                    ((io.reactivex.rxjava3.core.q) this.d).a(this);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object it2) {
        switch (this.a) {
            case 0:
                if (!this.c) {
                    try {
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (Intrinsics.b(it2, Boolean.TRUE)) {
                            this.c = true;
                            this.b.dispose();
                            Boolean bool = Boolean.TRUE;
                            io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.d;
                            lVar.b(bool);
                            lVar.onComplete();
                            break;
                        }
                    } catch (Throwable th) {
                        x7.b(th);
                        this.b.dispose();
                        onError(th);
                        return;
                    }
                }
                break;
            default:
                if (!this.c) {
                    try {
                        Intrinsics.checkNotNullParameter(it2, "it");
                        if (Intrinsics.b(it2, Boolean.TRUE)) {
                            this.c = true;
                            this.b.dispose();
                            ((io.reactivex.rxjava3.core.q) this.d).onSuccess(Boolean.TRUE);
                            break;
                        }
                    } catch (Throwable th2) {
                        x7.b(th2);
                        this.b.dispose();
                        onError(th2);
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.b.dispose();
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
                if (!this.c) {
                    this.c = true;
                    Boolean bool = Boolean.FALSE;
                    io.reactivex.rxjava3.core.l lVar = (io.reactivex.rxjava3.core.l) this.d;
                    lVar.b(bool);
                    lVar.onComplete();
                    break;
                }
                break;
            default:
                if (!this.c) {
                    this.c = true;
                    ((io.reactivex.rxjava3.core.q) this.d).onSuccess(Boolean.FALSE);
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                if (!this.c) {
                    this.c = true;
                    ((io.reactivex.rxjava3.core.l) this.d).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
            default:
                if (!this.c) {
                    this.c = true;
                    ((io.reactivex.rxjava3.core.q) this.d).onError(th);
                    break;
                } else {
                    C7.c(th);
                    break;
                }
        }
    }
}
