package io.reactivex.rxjava3.internal.operators.observable;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes3.dex */
public final class g0 extends io.reactivex.rxjava3.core.i {
    public final long a = 0 + SubsamplingScaleImageView.TILE_SIZE_AUTO;

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        io.reactivex.rxjava3.core.l lVar2;
        f0 f0Var = new f0(lVar, 0, this.a);
        lVar.a(f0Var);
        if (f0Var.d) {
            return;
        }
        long j = f0Var.c;
        while (true) {
            long j2 = f0Var.b;
            lVar2 = f0Var.a;
            if (j == j2 || f0Var.get() != 0) {
                break;
            }
            lVar2.b(Integer.valueOf((int) j));
            j++;
        }
        if (f0Var.get() == 0) {
            f0Var.lazySet(1);
            lVar2.onComplete();
        }
    }
}
