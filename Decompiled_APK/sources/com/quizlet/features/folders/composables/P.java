package com.quizlet.features.folders.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class P implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.l c;
    public final /* synthetic */ int d;

    public /* synthetic */ P(Function1 function1, com.quizlet.ui.models.content.listitem.l lVar, int i, int i2) {
        this.a = i2;
        this.b = function1;
        this.c = lVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(new com.quizlet.features.folders.data.L(false, this.c.a.a, this.d));
                break;
            default:
                this.b.invoke(new com.quizlet.features.folders.data.L(true, this.c.a.a, this.d));
                break;
        }
        return Unit.a;
    }
}
