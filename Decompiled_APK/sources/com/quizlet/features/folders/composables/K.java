package com.quizlet.features.folders.composables;

import com.quizlet.features.folders.data.C4313w;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class K implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.o c;
    public final /* synthetic */ int d;

    public /* synthetic */ K(Function1 function1, com.quizlet.ui.models.content.listitem.o oVar, int i, int i2) {
        this.a = i2;
        this.b = function1;
        this.c = oVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(new C4313w(this.c, this.d, false));
                break;
            default:
                this.b.invoke(new C4313w(this.c, this.d, true));
                break;
        }
        return Unit.a;
    }
}
