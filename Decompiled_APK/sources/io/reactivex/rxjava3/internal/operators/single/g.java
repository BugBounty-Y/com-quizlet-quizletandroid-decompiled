package io.reactivex.rxjava3.internal.operators.single;

/* loaded from: classes3.dex */
public final class g extends io.reactivex.rxjava3.core.p {
    public final /* synthetic */ int a;
    public final io.reactivex.rxjava3.core.p b;
    public final io.reactivex.rxjava3.functions.h c;

    public /* synthetic */ g(io.reactivex.rxjava3.core.p pVar, io.reactivex.rxjava3.functions.h hVar, int i) {
        this.a = i;
        this.c = hVar;
        this.b = pVar;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(io.reactivex.rxjava3.core.q qVar) {
        switch (this.a) {
            case 0:
                this.b.j(new f(0, qVar, this.c));
                break;
            case 1:
                this.b.j(new com.quizlet.remote.model.user.emailconfirmation.c(qVar, this.c));
                break;
            default:
                this.b.j(new f(1, qVar, this.c));
                break;
        }
    }
}
