package io.reactivex.rxjava3.internal.operators.flowable;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.n;

/* loaded from: classes3.dex */
public final class c extends io.reactivex.rxjava3.core.e {
    public final /* synthetic */ int b;
    public final Object c;

    public /* synthetic */ c(Object obj, int i) {
        this.b = i;
        this.c = obj;
    }

    @Override // io.reactivex.rxjava3.core.e
    public final void b(io.reactivex.rxjava3.core.f fVar) {
        Object obj = this.c;
        switch (this.b) {
            case 0:
                try {
                    th = ((io.reactivex.rxjava3.internal.functions.c) obj).a;
                } catch (Throwable th) {
                    th = th;
                    x7.b(th);
                }
                if (th == null) {
                    throw io.reactivex.rxjava3.internal.util.c.a("Callable returned a null Throwable.");
                }
                C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                fVar.c(io.reactivex.rxjava3.internal.subscriptions.b.a);
                fVar.onError(th);
                return;
            case 1:
                ((i) obj).c(new d(fVar));
                return;
            default:
                ((p) obj).j(new n(fVar));
                return;
        }
    }
}
