package com.quizlet.features.infra.folder.create.coursefolder.composable;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ com.quizlet.features.infra.models.folders.c c;

    public /* synthetic */ i(Function1 function1, com.quizlet.features.infra.models.folders.c cVar, int i) {
        this.a = i;
        this.b = function1;
        this.c = cVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(this.c);
                break;
            default:
                this.b.invoke(this.c);
                break;
        }
        return Unit.a;
    }
}
