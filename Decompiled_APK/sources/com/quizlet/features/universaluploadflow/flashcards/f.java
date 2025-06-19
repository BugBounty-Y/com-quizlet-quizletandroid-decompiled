package com.quizlet.features.universaluploadflow.flashcards;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.features.universaluploadflow.flashcards.data.a c;

    public /* synthetic */ f(Function1 function1, com.quizlet.features.universaluploadflow.flashcards.data.a aVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = aVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(Long.valueOf(this.c.a.a));
                break;
            default:
                this.b.invoke(Long.valueOf(this.c.a.a));
                break;
        }
        return Unit.a;
    }
}
