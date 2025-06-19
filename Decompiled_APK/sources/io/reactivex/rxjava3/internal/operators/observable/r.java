package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.y7;

/* loaded from: classes3.dex */
public final class r extends AbstractC4882a {
    public final int b;

    public r(io.reactivex.rxjava3.core.i iVar, int i) {
        super(iVar);
        this.b = Math.max(8, i);
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        com.quizlet.quizletandroid.ui.profile.p pVar = io.reactivex.rxjava3.internal.functions.d.a;
        io.reactivex.rxjava3.core.k kVar = this.a;
        if (y7.f(kVar, lVar, pVar)) {
            return;
        }
        kVar.c(new C4898q(lVar, this.b));
    }
}
