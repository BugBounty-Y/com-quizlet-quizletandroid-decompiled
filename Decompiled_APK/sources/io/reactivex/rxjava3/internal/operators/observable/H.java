package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.y7;

/* loaded from: classes3.dex */
public final class H extends AbstractC4882a {
    public final io.reactivex.rxjava3.functions.h b;
    public final int c;
    public final int d;

    public H(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.h hVar, int i, int i2) {
        super(iVar);
        this.b = hVar;
        this.c = i;
        this.d = i2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        io.reactivex.rxjava3.functions.h hVar = this.b;
        io.reactivex.rxjava3.core.k kVar = this.a;
        if (y7.f(kVar, lVar, hVar)) {
            return;
        }
        kVar.c(new G(lVar, hVar, this.c, this.d));
    }
}
