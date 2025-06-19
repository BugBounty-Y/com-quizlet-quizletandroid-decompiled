package com.quizlet.search.composables;

import com.quizlet.data.model.Y;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.search.viewmodels.x b;
    public final /* synthetic */ String c;

    public /* synthetic */ r(com.quizlet.search.viewmodels.x xVar, String str, int i) {
        this.a = i;
        this.b = xVar;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.C(this.c);
            default:
                com.quizlet.search.viewmodels.x xVar = this.b;
                return new com.quizlet.search.paging.d(xVar.h, this.c, kotlin.collections.A.b(Y.QUESTION), xVar.j, xVar);
        }
    }
}
