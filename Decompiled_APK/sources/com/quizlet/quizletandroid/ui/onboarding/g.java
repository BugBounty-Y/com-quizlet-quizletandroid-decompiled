package com.quizlet.quizletandroid.ui.onboarding;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B5;
import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.n;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class g extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objB;
        Object value;
        b bVar;
        B5 currentStep;
        s0 s0Var;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            Z.e(obj);
            a aVar2 = hVar.c;
            this.j = 1;
            aVar2.getClass();
            p pVar = r.b;
            objB = Z.b(new n(null, 1, null));
            if (objB == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objB = ((r) obj).a;
        }
        p pVar2 = r.b;
        if (!(objB instanceof q)) {
            QuestionnaireModel questionnaireModel = (QuestionnaireModel) objB;
            hVar.b.c(questionnaireModel, "questionnaire_model");
            f currentStep2 = new f(questionnaireModel);
            do {
                s0Var = hVar.d;
                value2 = s0Var.getValue();
                ((d) value2).getClass();
                Intrinsics.checkNotNullParameter(currentStep2, "currentStep");
            } while (!s0Var.k(value2, new d(currentStep2, null)));
        }
        if (r.a(objB) != null) {
            s0 s0Var2 = hVar.d;
            do {
                value = s0Var2.getValue();
                bVar = b.a;
                currentStep = ((d) value).a;
                Intrinsics.checkNotNullParameter(currentStep, "currentStep");
            } while (!s0Var2.k(value, new d(currentStep, bVar)));
        }
        return Unit.a;
    }
}
