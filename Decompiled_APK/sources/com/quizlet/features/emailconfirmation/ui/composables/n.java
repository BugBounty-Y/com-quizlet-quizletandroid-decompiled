package com.quizlet.features.emailconfirmation.ui.composables;

import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ float b;

    public n(float f, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = f;
                break;
            default:
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                this.b = f;
                break;
        }
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.constraintlayout.compose.a constrainAs = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar = constrainAs.f;
                androidx.constraintlayout.compose.b bVar = constrainAs.b;
                androidx.constraintlayout.compose.c cVar2 = bVar.f;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.v();
                float f = com.quizlet.ui.resources.designsystem.generated.j.l * this.b;
                com.quizlet.data.repository.qclass.c.o(cVar, cVar2, f, 4);
                mVar.v();
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs.e, bVar.e, f, 4);
                break;
            default:
                androidx.constraintlayout.compose.a constrainAs2 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs2, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar3 = constrainAs2.f;
                androidx.constraintlayout.compose.b bVar2 = constrainAs2.b;
                com.quizlet.data.repository.qclass.c.o(cVar3, bVar2.f, ContentType.LONG_FORM_ON_DEMAND * this.b, 4);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs2.c, bVar2.c, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs2.e, bVar2.e, DefinitionKt.NO_Float_VALUE, 6);
                break;
        }
        return Unit.a;
    }
}
