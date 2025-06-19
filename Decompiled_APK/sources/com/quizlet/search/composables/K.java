package com.quizlet.search.composables;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class K implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.search.viewmodels.G b;
    public final /* synthetic */ String c;

    public /* synthetic */ K(com.quizlet.search.viewmodels.G g, String str, int i) {
        this.a = i;
        this.b = g;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.C(this.c);
            default:
                com.quizlet.search.viewmodels.G g = this.b;
                return new com.quizlet.search.paging.b(g.h, this.c, g.i, g);
        }
    }
}
