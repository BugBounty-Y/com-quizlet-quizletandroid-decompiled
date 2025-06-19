package io.reactivex.rxjava3.internal.operators.observable;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4887f extends AbstractC4882a {
    public final /* synthetic */ int b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4887f(io.reactivex.rxjava3.core.k kVar, int i) {
        super(kVar);
        this.b = i;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                this.a.c(new C4886e(lVar, 0));
                break;
            case 1:
                this.a.c(new C4903w(lVar));
                break;
            case 2:
                this.a.c(new X(lVar, 0));
                break;
            case 3:
                this.a.c(new X(lVar, 1));
                break;
            case 4:
                this.a.c(new l0(lVar));
                break;
            default:
                this.a.c(new r0(lVar));
                break;
        }
    }
}
