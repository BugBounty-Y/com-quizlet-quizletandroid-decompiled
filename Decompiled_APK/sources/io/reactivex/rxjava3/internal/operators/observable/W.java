package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.y7;

/* loaded from: classes3.dex */
public final class W extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final int c;
    public final Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ W(io.reactivex.rxjava3.core.k kVar, Object obj, int i, int i2) {
        super(kVar);
        this.b = i2;
        this.d = obj;
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                this.a.c(new T(lVar, (com.quizlet.infra.legacysyncengine.net.sync.a) this.d, this.c));
                break;
            case 1:
                io.reactivex.rxjava3.core.o oVar = (io.reactivex.rxjava3.core.o) this.d;
                boolean z = oVar instanceof io.reactivex.rxjava3.internal.schedulers.w;
                io.reactivex.rxjava3.core.k kVar = this.a;
                if (!z) {
                    kVar.c(new b0(lVar, oVar.a(), this.c));
                    break;
                } else {
                    kVar.c(lVar);
                    break;
                }
            default:
                com.quizlet.data.repository.searchexplanations.c cVar = (com.quizlet.data.repository.searchexplanations.c) this.d;
                io.reactivex.rxjava3.core.k kVar2 = this.a;
                if (!y7.f(kVar2, lVar, cVar)) {
                    kVar2.c(new q0(lVar, cVar, this.c));
                    break;
                }
                break;
        }
    }
}
