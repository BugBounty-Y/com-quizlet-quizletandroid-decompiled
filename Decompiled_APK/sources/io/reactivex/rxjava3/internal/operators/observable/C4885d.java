package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Collection;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4885d extends io.reactivex.rxjava3.core.p implements io.reactivex.rxjava3.internal.fuseable.a {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.i b;
    public final Object c;

    public /* synthetic */ C4885d(io.reactivex.rxjava3.core.i iVar, Object obj, int i) {
        this.a = i;
        this.b = iVar;
        this.c = obj;
    }

    @Override // io.reactivex.rxjava3.internal.fuseable.a
    public final io.reactivex.rxjava3.core.i c() {
        switch (this.a) {
            case 0:
                return new C4884c(this.b, (io.reactivex.rxjava3.functions.i) this.c, 0);
            case 1:
                return new C4905y(this.b, (kotlin.collections.K) this.c, 2);
            default:
                return new C4905y(this.b, (io.reactivex.rxjava3.internal.functions.a) this.c, 3);
        }
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        int i = 1;
        io.reactivex.rxjava3.core.i iVar = this.b;
        Object obj = this.c;
        switch (this.a) {
            case 0:
                iVar.c(new C4883b(qVar, (io.reactivex.rxjava3.functions.i) obj, 1));
                break;
            case 1:
                iVar.c(new D(qVar, (kotlin.collections.K) obj, i));
                break;
            default:
                try {
                    Object obj2 = ((io.reactivex.rxjava3.internal.functions.a) obj).get();
                    C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                    iVar.c(new a0(qVar, (Collection) obj2, 2));
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    qVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
                    qVar.onError(th);
                    return;
                }
        }
    }

    public C4885d(io.reactivex.rxjava3.core.i iVar, int i) {
        this.a = 2;
        this.b = iVar;
        this.c = new io.reactivex.rxjava3.internal.functions.a(i);
    }
}
