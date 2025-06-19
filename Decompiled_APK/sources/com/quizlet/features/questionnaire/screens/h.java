package com.quizlet.features.questionnaire.screens;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class h implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.questionnaire.navigation.b b;
    public final /* synthetic */ com.quizlet.features.questionnaire.steps.h c;
    public final /* synthetic */ com.quizlet.data.interactor.course.a d;
    public final /* synthetic */ q e;

    public /* synthetic */ h(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, q qVar, int i, int i2) {
        this.a = i2;
        this.b = bVar;
        this.c = hVar;
        this.d = aVar;
        this.e = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(1);
                com.quizlet.data.interactor.course.a aVar = this.d;
                q qVar = this.e;
                l.a(this.b, this.c, aVar, qVar, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.data.interactor.course.a aVar2 = this.d;
                q qVar2 = this.e;
                l.b(this.b, this.c, aVar2, qVar2, (InterfaceC0806l) obj, iH2);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(1);
                com.quizlet.data.interactor.course.a aVar3 = this.d;
                q qVar3 = this.e;
                l.f(this.b, this.c, aVar3, qVar3, (InterfaceC0806l) obj, iH3);
                break;
        }
        return Unit.a;
    }
}
