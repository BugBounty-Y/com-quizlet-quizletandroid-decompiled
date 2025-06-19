package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Collection;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4905y extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4905y(io.reactivex.rxjava3.core.i iVar, Object obj, int i) {
        super(iVar);
        this.b = i;
        this.c = obj;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        io.reactivex.rxjava3.core.k kVar = this.a;
        Object obj = this.c;
        switch (this.b) {
            case 0:
                kVar.c(new C4904x(lVar, (io.reactivex.rxjava3.functions.d) obj, 0));
                break;
            case 1:
                kVar.c(new C4906z(lVar, (io.reactivex.rxjava3.functions.a) obj));
                break;
            case 2:
                kVar.c(new D(lVar, (kotlin.collections.K) obj, 0));
                break;
            default:
                try {
                    Object obj2 = ((io.reactivex.rxjava3.internal.functions.a) obj).get();
                    C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                    kVar.c(new a0(lVar, (Collection) obj2, 1));
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    io.reactivex.rxjava3.internal.disposables.b.d(th, lVar);
                    return;
                }
        }
    }
}
