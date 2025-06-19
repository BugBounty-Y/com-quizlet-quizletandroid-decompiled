package com.quizlet.features.questionnaire.screens;

import androidx.compose.foundation.layout.FillElement;
import androidx.compose.foundation.layout.K0;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.m;
import androidx.navigation.C1291m;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ com.quizlet.features.questionnaire.navigation.b b;
    public final /* synthetic */ com.quizlet.features.questionnaire.steps.h c;
    public final /* synthetic */ com.quizlet.data.interactor.course.a d;

    public /* synthetic */ i(com.quizlet.features.questionnaire.navigation.b bVar, com.quizlet.features.questionnaire.steps.h hVar, com.quizlet.data.interactor.course.a aVar, int i) {
        this.a = i;
        this.b = bVar;
        this.c = hVar;
        this.d = aVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                C1291m it2 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it2, "it");
                FillElement fillElement = K0.c;
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(1445299268);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = new com.quizlet.features.practicetest.navigation.a(9);
                    c0814p.i0(objI);
                }
                c0814p.p(false);
                q qVarA = m.a(fillElement, false, (Function1) objI);
                l.b(this.b, this.c, this.d, qVarA, c0814p, 0);
                break;
            case 1:
                C1291m it3 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it3, "it");
                FillElement fillElement2 = K0.c;
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(1445310884);
                Object objI2 = c0814p2.I();
                if (objI2 == C0804k.a) {
                    objI2 = new com.quizlet.features.practicetest.navigation.a(10);
                    c0814p2.i0(objI2);
                }
                c0814p2.p(false);
                q qVarA2 = m.a(fillElement2, false, (Function1) objI2);
                l.a(this.b, this.c, this.d, qVarA2, c0814p2, 0);
                break;
            default:
                C1291m it4 = (C1291m) obj;
                ((Number) obj3).intValue();
                Intrinsics.checkNotNullParameter(it4, "it");
                FillElement fillElement3 = K0.c;
                C0814p c0814p3 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p3.X(1445322828);
                Object objI3 = c0814p3.I();
                if (objI3 == C0804k.a) {
                    objI3 = new com.quizlet.features.practicetest.navigation.a(11);
                    c0814p3.i0(objI3);
                }
                c0814p3.p(false);
                q qVarA3 = m.a(fillElement3, false, (Function1) objI3);
                l.f(this.b, this.c, this.d, qVarA3, c0814p3, 0);
                break;
        }
        return Unit.a;
    }
}
