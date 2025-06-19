package com.quizlet.features.infra.folder.tag.composable;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.features.infra.folder.tag.screenstates.k c;

    public /* synthetic */ j(Function1 function1, com.quizlet.features.infra.folder.tag.screenstates.k kVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = kVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(new com.quizlet.features.infra.folder.tag.screenstates.i(this.c.a));
                break;
            default:
                this.b.invoke(new com.quizlet.features.infra.folder.tag.screenstates.i(this.c.a));
                break;
        }
        return Unit.a;
    }
}
