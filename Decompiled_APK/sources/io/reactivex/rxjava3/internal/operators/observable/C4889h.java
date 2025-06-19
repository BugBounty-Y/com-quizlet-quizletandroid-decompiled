package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.ArrayList;
import java.util.Collection;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4889h implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final int b;
    public Collection c;
    public int d;
    public io.reactivex.rxjava3.disposables.b e;

    public C4889h(io.reactivex.rxjava3.core.l lVar, int i) {
        this.a = lVar;
        this.b = i;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.e, bVar)) {
            this.e = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        Collection collection = this.c;
        if (collection != null) {
            collection.add(obj);
            int i = this.d + 1;
            this.d = i;
            if (i >= this.b) {
                this.a.b(collection);
                this.d = 0;
                c();
            }
        }
    }

    public final boolean c() {
        try {
            this.c = new ArrayList();
            return true;
        } catch (Throwable th) {
            x7.b(th);
            this.c = null;
            io.reactivex.rxjava3.disposables.b bVar = this.e;
            io.reactivex.rxjava3.core.l lVar = this.a;
            if (bVar == null) {
                io.reactivex.rxjava3.internal.disposables.b.d(th, lVar);
                return false;
            }
            bVar.dispose();
            lVar.onError(th);
            return false;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        Collection collection = this.c;
        if (collection != null) {
            this.c = null;
            boolean zIsEmpty = collection.isEmpty();
            io.reactivex.rxjava3.core.l lVar = this.a;
            if (!zIsEmpty) {
                lVar.b(collection);
            }
            lVar.onComplete();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        this.c = null;
        this.a.onError(th);
    }
}
