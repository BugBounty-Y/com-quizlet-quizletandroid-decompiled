package io.reactivex.rxjava3.internal.operators.flowable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.exceptions.ProtocolViolationException;
import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class a implements io.reactivex.rxjava3.core.f, io.reactivex.rxjava3.disposables.b {
    public final q a;
    public org.reactivestreams.b b;
    public long c;
    public boolean d;

    public a(q qVar) {
        this.a = qVar;
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void b(Object obj) {
        if (this.d) {
            return;
        }
        long j = this.c;
        if (j != 0) {
            this.c = j + 1;
            return;
        }
        this.d = true;
        this.b.cancel();
        this.b = io.reactivex.rxjava3.internal.subscriptions.c.a;
        this.a.onSuccess(obj);
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void c(org.reactivestreams.b bVar) {
        boolean z;
        if (this.b != null) {
            bVar.cancel();
            C7.c(new ProtocolViolationException("Subscription already set!"));
            z = false;
        } else {
            z = true;
        }
        if (z) {
            this.b = bVar;
            this.a.a(this);
            bVar.e(1L);
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.b.cancel();
        this.b = io.reactivex.rxjava3.internal.subscriptions.c.a;
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onComplete() {
        this.b = io.reactivex.rxjava3.internal.subscriptions.c.a;
        if (this.d) {
            return;
        }
        this.d = true;
        this.a.onError(new NoSuchElementException());
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onError(Throwable th) {
        if (this.d) {
            C7.c(th);
            return;
        }
        this.d = true;
        this.b = io.reactivex.rxjava3.internal.subscriptions.c.a;
        this.a.onError(th);
    }
}
