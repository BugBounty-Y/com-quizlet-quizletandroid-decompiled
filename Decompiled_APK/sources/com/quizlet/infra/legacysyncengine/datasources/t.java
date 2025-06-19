package com.quizlet.infra.legacysyncengine.datasources;

/* loaded from: classes3.dex */
public final /* synthetic */ class t implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ w b;

    public /* synthetic */ t(w wVar, int i) {
        this.a = i;
        this.b = wVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        com.quizlet.infra.legacysyncengine.net.request.c cVar = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
        switch (this.a) {
            case 0:
                this.b.g.b(cVar);
                break;
            default:
                this.b.g.b(cVar);
                break;
        }
    }
}
