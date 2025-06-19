package com.quizlet.features.infra.basestudy.data.models.dataproviders;

import java.util.List;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ a b;

    public /* synthetic */ c(a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        List list = (List) obj;
        switch (this.a) {
            case 0:
                a aVar = this.b;
                aVar.getClass();
                timber.log.c.a.g("All data sources have finished loading", new Object[0]);
                com.quizlet.qutils.rx.b bVar = aVar.F;
                if (bVar != null) {
                    bVar.run();
                }
                aVar.g.onComplete();
                break;
            case 1:
                this.b.v = list;
                break;
            case 2:
                this.b.w = list;
                break;
            default:
                this.b.x = list;
                break;
        }
    }
}
