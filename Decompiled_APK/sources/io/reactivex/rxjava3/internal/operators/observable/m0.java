package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.measurement.internal.A0;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class m0 extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.core.o c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m0(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.core.o oVar, int i) {
        super(iVar);
        this.b = i;
        switch (i) {
            case 2:
                TimeUnit timeUnit = TimeUnit.SECONDS;
                super(iVar);
                this.c = oVar;
                break;
            default:
                this.c = oVar;
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                io.reactivex.rxjava3.internal.operators.mixed.a aVar = new io.reactivex.rxjava3.internal.operators.mixed.a(lVar);
                lVar.a(aVar);
                io.reactivex.rxjava3.internal.disposables.a.e(aVar, this.c.b(new A0(14, this, aVar)));
                break;
            case 1:
                io.reactivex.rxjava3.observers.a aVar2 = new io.reactivex.rxjava3.observers.a(lVar);
                io.reactivex.rxjava3.core.n nVarA = this.c.a();
                TimeUnit timeUnit = TimeUnit.MILLISECONDS;
                this.a.c(new u0(aVar2, nVarA));
                break;
            default:
                TimeUnit timeUnit2 = TimeUnit.SECONDS;
                v0 v0Var = new v0(lVar, this.c.a());
                lVar.a(v0Var);
                io.reactivex.rxjava3.disposables.b bVarB = v0Var.d.b(new com.google.ads.conversiontracking.i(0L, v0Var), v0Var.b, v0Var.c);
                io.reactivex.rxjava3.disposables.d dVar = v0Var.e;
                dVar.getClass();
                io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVarB);
                this.a.c(v0Var);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m0(com.jakewharton.rxbinding4.a aVar, io.reactivex.rxjava3.core.o oVar) {
        super(aVar);
        this.b = 1;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        this.c = oVar;
    }
}
