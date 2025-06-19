package io.reactivex.rxjava3.internal.operators.observable;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4884c extends AbstractC4882a {
    public final /* synthetic */ int b;
    public final io.reactivex.rxjava3.functions.i c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4884c(io.reactivex.rxjava3.core.i iVar, io.reactivex.rxjava3.functions.i iVar2, int i) {
        super(iVar);
        this.b = i;
        this.c = iVar2;
    }

    @Override // io.reactivex.rxjava3.core.i
    public final void v(io.reactivex.rxjava3.core.l lVar) {
        switch (this.b) {
            case 0:
                this.a.c(new C4883b(lVar, this.c, 0));
                break;
            default:
                this.a.c(new C4904x(lVar, this.c, 1));
                break;
        }
    }
}
