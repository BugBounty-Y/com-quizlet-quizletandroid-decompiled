package com.quizlet.features.emailconfirmation.ui.composables;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.constraintlayout.compose.b b;

    public /* synthetic */ i(androidx.constraintlayout.compose.b bVar, int i) {
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.constraintlayout.compose.a constrainAs = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar = constrainAs.f;
                androidx.constraintlayout.compose.b bVar = this.b;
                com.quizlet.data.repository.qclass.c.o(cVar, bVar.d, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c cVar2 = constrainAs.c;
                androidx.constraintlayout.compose.d dVar = bVar.e;
                com.quizlet.data.repository.searchexplanations.c.j(cVar2, dVar, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs.e, dVar, DefinitionKt.NO_Float_VALUE, 6);
                break;
            case 1:
                androidx.constraintlayout.compose.a constrainAs2 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs2, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar3 = constrainAs2.f;
                androidx.constraintlayout.compose.b bVar2 = this.b;
                com.quizlet.data.repository.qclass.c.o(cVar3, bVar2.d, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c cVar4 = constrainAs2.c;
                androidx.constraintlayout.compose.d dVar2 = bVar2.e;
                com.quizlet.data.repository.searchexplanations.c.j(cVar4, dVar2, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs2.e, dVar2, DefinitionKt.NO_Float_VALUE, 6);
                break;
            default:
                androidx.constraintlayout.compose.a constrainAs3 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs3, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c.o(constrainAs3.d, this.b.f, DefinitionKt.NO_Float_VALUE, 6);
                androidx.constraintlayout.compose.b bVar3 = constrainAs3.b;
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs3.c, bVar3.c, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs3.e, bVar3.e, DefinitionKt.NO_Float_VALUE, 6);
                break;
        }
        return Unit.a;
    }
}
