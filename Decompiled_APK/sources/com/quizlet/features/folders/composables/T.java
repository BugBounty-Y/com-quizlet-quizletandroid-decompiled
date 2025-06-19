package com.quizlet.features.folders.composables;

import com.quizlet.features.folders.data.C4319z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class T implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.ui.models.content.listitem.i c;
    public final /* synthetic */ int d;

    public /* synthetic */ T(Function1 function1, com.quizlet.ui.models.content.listitem.i iVar, int i, int i2) {
        this.a = i2;
        this.b = function1;
        this.c = iVar;
        this.d = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(new C4319z(this.c.a.a, this.d, false));
                break;
            default:
                this.b.invoke(new C4319z(this.c.a.a, this.d, true));
                break;
        }
        return Unit.a;
    }
}
