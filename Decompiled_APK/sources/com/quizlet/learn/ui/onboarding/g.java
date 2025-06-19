package com.quizlet.learn.ui.onboarding;

import androidx.compose.runtime.InterfaceC0773a0;
import assistantMode.enums.y;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.learn.viewmodel.i b;
    public final /* synthetic */ InterfaceC0773a0 c;
    public final /* synthetic */ InterfaceC0773a0 d;

    public /* synthetic */ g(com.quizlet.learn.viewmodel.i iVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, int i) {
        this.a = i;
        this.b = iVar;
        this.c = interfaceC0773a0;
        this.d = interfaceC0773a02;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                InterfaceC0773a0 interfaceC0773a0 = this.c;
                interfaceC0773a0.setValue((com.quizlet.studiablemodels.assistantMode.a) obj);
                this.b.B(new com.quizlet.learn.data.onboarding.f((com.quizlet.studiablemodels.assistantMode.a) interfaceC0773a0.getValue(), (y) this.d.getValue()));
                break;
            case 1:
                InterfaceC0773a0 interfaceC0773a02 = this.c;
                interfaceC0773a02.setValue((y) obj);
                this.b.B(new com.quizlet.learn.data.onboarding.f((com.quizlet.studiablemodels.assistantMode.a) this.d.getValue(), (y) interfaceC0773a02.getValue()));
                break;
            case 2:
                InterfaceC0773a0 interfaceC0773a03 = this.c;
                interfaceC0773a03.setValue((com.quizlet.studiablemodels.assistantMode.a) obj);
                this.b.B(new com.quizlet.learn.data.onboarding.f((com.quizlet.studiablemodels.assistantMode.a) interfaceC0773a03.getValue(), (y) this.d.getValue()));
                break;
            default:
                InterfaceC0773a0 interfaceC0773a04 = this.c;
                interfaceC0773a04.setValue((y) obj);
                this.b.B(new com.quizlet.learn.data.onboarding.f((com.quizlet.studiablemodels.assistantMode.a) this.d.getValue(), (y) interfaceC0773a04.getValue()));
                break;
        }
        return Unit.a;
    }
}
