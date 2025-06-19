package com.quizlet.features.questiontypes.written.ui;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.questiontypes.written.a b;

    public /* synthetic */ e(com.quizlet.features.questiontypes.written.a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((com.quizlet.features.questiontypes.written.o) this.b).F(com.quizlet.features.questiontypes.written.c.a);
                break;
            default:
                ((com.quizlet.features.questiontypes.written.o) this.b).F(com.quizlet.features.questiontypes.written.d.a);
                break;
        }
        return Unit.a;
    }
}
