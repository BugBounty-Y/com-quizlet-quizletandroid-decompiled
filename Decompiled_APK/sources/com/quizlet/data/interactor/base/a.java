package com.quizlet.data.interactor.base;

/* loaded from: classes2.dex */
public final class a implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.cache.a b;
    public final /* synthetic */ Long c;

    public /* synthetic */ a(com.quizlet.cache.a aVar, Long l, int i) {
        this.a = i;
        this.b = aVar;
        this.c = l;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.b(this.c);
                break;
            default:
                this.b.b(this.c);
                break;
        }
    }
}
