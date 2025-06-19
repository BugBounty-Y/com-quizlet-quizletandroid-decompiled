package io.reactivex.rxjava3.core;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import java.util.Objects;

/* loaded from: classes3.dex */
public abstract class g {
    public static io.reactivex.rxjava3.internal.operators.maybe.c b(io.reactivex.rxjava3.internal.operators.maybe.e eVar, io.reactivex.rxjava3.internal.operators.maybe.e eVar2) {
        return new io.reactivex.rxjava3.internal.operators.maybe.c(new g[]{eVar, eVar2}, 0);
    }

    public static io.reactivex.rxjava3.internal.operators.maybe.l c(Object obj) {
        Objects.requireNonNull(obj, "item is null");
        return new io.reactivex.rxjava3.internal.operators.maybe.l(obj);
    }

    public static io.reactivex.rxjava3.internal.operators.maybe.c d(io.reactivex.rxjava3.internal.operators.maybe.h hVar, io.reactivex.rxjava3.internal.operators.maybe.e eVar) {
        return new io.reactivex.rxjava3.internal.operators.maybe.c(new g[]{hVar, eVar}, 1);
    }

    public final void e(h hVar) {
        try {
            f(hVar);
        } catch (NullPointerException e) {
            throw e;
        } catch (Throwable th) {
            x7.b(th);
            NullPointerException nullPointerException = new NullPointerException("subscribeActual failed");
            nullPointerException.initCause(th);
            throw nullPointerException;
        }
    }

    public abstract void f(h hVar);

    /* JADX WARN: Multi-variable type inference failed */
    public final i g() {
        return this instanceof io.reactivex.rxjava3.internal.fuseable.a ? ((io.reactivex.rxjava3.internal.fuseable.a) this).c() : new com.jakewharton.rxbinding4.a(this, 2);
    }

    public final w h() {
        return new w(0, this, null);
    }
}
