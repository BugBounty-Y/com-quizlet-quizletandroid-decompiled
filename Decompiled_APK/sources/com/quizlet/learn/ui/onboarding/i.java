package com.quizlet.learn.ui.onboarding;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.learn.viewmodel.i b;

    public /* synthetic */ i(com.quizlet.learn.viewmodel.i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.B(com.quizlet.learn.data.onboarding.g.a);
                break;
            case 1:
                this.b.B(com.quizlet.learn.data.onboarding.e.a);
                break;
            case 2:
                this.b.B(com.quizlet.learn.data.onboarding.g.a);
                break;
            case 3:
                this.b.B(com.quizlet.learn.data.onboarding.g.a);
                break;
            default:
                this.b.B(com.quizlet.learn.data.onboarding.e.a);
                break;
        }
        return Unit.a;
    }
}
