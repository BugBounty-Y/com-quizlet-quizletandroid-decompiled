package io.reactivex.rxjava3.observers;

import androidx.appcompat.widget.C0122z;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.disposables.b;
import io.reactivex.rxjava3.internal.util.c;
import io.reactivex.rxjava3.internal.util.d;
import io.reactivex.rxjava3.internal.util.e;

/* loaded from: classes3.dex */
public final class a implements l, b {
    public final l a;
    public b b;
    public boolean c;
    public C0122z d;
    public volatile boolean e;

    public a(l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.b, bVar)) {
            this.b = bVar;
            this.a.a(this);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        Object obj2;
        if (this.e) {
            return;
        }
        if (obj == null) {
            this.b.dispose();
            onError(c.a("onNext called with a null value."));
            return;
        }
        synchronized (this) {
            try {
                if (this.e) {
                    return;
                }
                if (this.c) {
                    C0122z c0122z = this.d;
                    if (c0122z == null) {
                        c0122z = new C0122z(21, (byte) 0);
                        this.d = c0122z;
                    }
                    c0122z.b(obj);
                    return;
                }
                this.c = true;
                this.a.b(obj);
                while (true) {
                    synchronized (this) {
                        try {
                            C0122z c0122z2 = this.d;
                            if (c0122z2 == null) {
                                this.c = false;
                                return;
                            }
                            this.d = null;
                            l lVar = this.a;
                            for (Object[] objArr = (Object[]) c0122z2.c; objArr != null; objArr = objArr[4]) {
                                for (int i = 0; i < 4 && (obj2 = objArr[i]) != null; i++) {
                                    if (obj2 == e.a) {
                                        lVar.onComplete();
                                        return;
                                    } else {
                                        if (obj2 instanceof d) {
                                            lVar.onError(((d) obj2).a);
                                            return;
                                        }
                                        lVar.b(obj2);
                                    }
                                }
                            }
                        } finally {
                        }
                    }
                }
            } finally {
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e = true;
        this.b.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.e) {
            return;
        }
        synchronized (this) {
            try {
                if (this.e) {
                    return;
                }
                if (!this.c) {
                    this.e = true;
                    this.c = true;
                    this.a.onComplete();
                } else {
                    C0122z c0122z = this.d;
                    if (c0122z == null) {
                        c0122z = new C0122z(21, (byte) 0);
                        this.d = c0122z;
                    }
                    c0122z.b(e.a);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.e) {
            C7.c(th);
            return;
        }
        synchronized (this) {
            try {
                boolean z = true;
                if (!this.e) {
                    if (this.c) {
                        this.e = true;
                        C0122z c0122z = this.d;
                        if (c0122z == null) {
                            c0122z = new C0122z(21, (byte) 0);
                            this.d = c0122z;
                        }
                        ((Object[]) c0122z.c)[0] = new d(th);
                        return;
                    }
                    this.e = true;
                    this.c = true;
                    z = false;
                }
                if (z) {
                    C7.c(th);
                } else {
                    this.a.onError(th);
                }
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }
}
