package com.quizlet.features.folders.edittags.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.folders.edittags.viewmodel.c b;

    public /* synthetic */ c(com.quizlet.features.folders.edittags.viewmodel.c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.A(com.quizlet.features.folders.edittags.data.c.a);
                break;
            case 1:
                this.b.A(com.quizlet.features.folders.edittags.data.e.a);
                break;
            case 2:
                this.b.A(com.quizlet.features.folders.edittags.data.d.a);
                break;
            case 3:
                this.b.A(com.quizlet.features.folders.edittags.data.e.a);
                break;
            default:
                this.b.A(com.quizlet.features.folders.edittags.data.d.a);
                break;
        }
        return Unit.a;
    }
}
