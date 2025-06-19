package com.quizlet.features.emailconfirmation.ui.composables;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o implements Function1 {
    public final /* synthetic */ androidx.constraintlayout.compose.b a;
    public final /* synthetic */ float b;

    public o(androidx.constraintlayout.compose.b bVar, float f) {
        com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
        this.a = bVar;
        this.b = f;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.constraintlayout.compose.a constrainAs = (androidx.constraintlayout.compose.a) obj;
        Intrinsics.checkNotNullParameter(constrainAs, "$this$constrainAs");
        com.quizlet.data.repository.qclass.c cVar = constrainAs.f;
        androidx.constraintlayout.compose.b bVar = this.a;
        com.quizlet.themes.m.g.s();
        com.quizlet.data.repository.qclass.c.o(cVar, bVar.d, com.quizlet.ui.resources.designsystem.generated.j.h * this.b, 4);
        com.quizlet.data.repository.searchexplanations.c cVar2 = constrainAs.c;
        androidx.constraintlayout.compose.d dVar = bVar.c;
        com.quizlet.data.repository.searchexplanations.c.j(cVar2, dVar, DefinitionKt.NO_Float_VALUE, 6);
        com.quizlet.data.repository.searchexplanations.c.j(constrainAs.e, dVar, DefinitionKt.NO_Float_VALUE, 6);
        return Unit.a;
    }
}
