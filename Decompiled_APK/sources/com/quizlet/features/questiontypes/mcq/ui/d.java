package com.quizlet.features.questiontypes.mcq.ui;

import com.quizlet.features.questiontypes.mcq.l;
import com.quizlet.features.questiontypes.mcq.p;
import com.quizlet.features.questiontypes.mcq.t;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.questiontypes.mcq.a b;

    public /* synthetic */ d(com.quizlet.features.questiontypes.mcq.a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((l) this.b).B(p.a);
                break;
            default:
                ((l) this.b).B(t.a);
                break;
        }
        return Unit.a;
    }
}
