package com.quizlet.quizletandroid.ui.library;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.library.viewmodels.e c;

    public /* synthetic */ r(Function1 function1, com.quizlet.library.viewmodels.e eVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = eVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(((com.quizlet.library.viewmodels.t) this.c).b.a);
                break;
            default:
                this.b.invoke(((com.quizlet.library.viewmodels.t) this.c).a.a);
                break;
        }
        return Unit.a;
    }
}
