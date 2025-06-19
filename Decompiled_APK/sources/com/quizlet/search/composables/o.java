package com.quizlet.search.composables;

import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.search.viewmodels.u b;
    public final /* synthetic */ String c;

    public /* synthetic */ o(com.quizlet.search.viewmodels.u uVar, String str, int i) {
        this.a = i;
        this.b = uVar;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b.C(this.c);
            default:
                com.quizlet.search.viewmodels.u uVar = this.b;
                return new com.quizlet.search.paging.b(uVar.h, this.c, uVar.i, uVar);
        }
    }
}
