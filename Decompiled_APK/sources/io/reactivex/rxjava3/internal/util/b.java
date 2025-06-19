package io.reactivex.rxjava3.internal.util;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import io.reactivex.rxjava3.core.f;
import io.reactivex.rxjava3.core.l;
import io.reactivex.rxjava3.exceptions.CompositeException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class b extends AtomicReference {
    public final Throwable a() {
        C2245jv c2245jv = c.a;
        Throwable th = (Throwable) get();
        C2245jv c2245jv2 = c.a;
        return th != c2245jv2 ? (Throwable) getAndSet(c2245jv2) : th;
    }

    public final boolean b(Throwable th) {
        C2245jv c2245jv = c.a;
        while (true) {
            Throwable th2 = (Throwable) get();
            if (th2 == c.a) {
                return false;
            }
            Throwable compositeException = th2 == null ? th : new CompositeException(th2, th);
            while (!compareAndSet(th2, compositeException)) {
                if (get() != th2) {
                    break;
                }
            }
            return true;
        }
    }

    public final boolean c(Throwable th) {
        if (b(th)) {
            return true;
        }
        C7.c(th);
        return false;
    }

    public final void d() {
        Throwable thA = a();
        if (thA == null || thA == c.a) {
            return;
        }
        C7.c(thA);
    }

    public final void e(io.reactivex.rxjava3.core.b bVar) {
        Throwable thA = a();
        if (thA == null) {
            bVar.onComplete();
        } else if (thA != c.a) {
            bVar.onError(thA);
        }
    }

    public final void f(f fVar) {
        Throwable thA = a();
        if (thA == null) {
            fVar.onComplete();
        } else if (thA != c.a) {
            fVar.onError(thA);
        }
    }

    public final void g(l lVar) {
        Throwable thA = a();
        if (thA == null) {
            lVar.onComplete();
        } else if (thA != c.a) {
            lVar.onError(thA);
        }
    }
}
