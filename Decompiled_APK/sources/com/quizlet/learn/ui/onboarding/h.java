package com.quizlet.learn.ui.onboarding;

import androidx.compose.runtime.InterfaceC0773a0;
import assistantMode.enums.y;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.learn.viewmodel.i b;
    public final /* synthetic */ InterfaceC0773a0 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ h(com.quizlet.learn.viewmodel.i iVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, int i) {
        this.a = i;
        this.b = iVar;
        this.c = interfaceC0773a0;
        this.d = interfaceC0773a02;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.B(new com.quizlet.learn.data.onboarding.h((com.quizlet.studiablemodels.assistantMode.a) this.c.getValue(), (y) this.d.getValue()));
                break;
            default:
                this.b.B(new com.quizlet.learn.data.onboarding.h((com.quizlet.studiablemodels.assistantMode.a) this.c.getValue(), (y) this.d.getValue()));
                break;
        }
        return Unit.a;
    }
}
