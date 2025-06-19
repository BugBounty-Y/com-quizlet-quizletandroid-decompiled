package com.quizlet.features.notes.upload.composables.upload;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Function1 {
    public static final c a = new c();

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.constraintlayout.compose.a constrainAs = (androidx.constraintlayout.compose.a) obj;
        Intrinsics.checkNotNullParameter(constrainAs, "$this$constrainAs");
        com.quizlet.data.repository.qclass.c cVar = constrainAs.d;
        androidx.constraintlayout.compose.b bVar = constrainAs.b;
        com.quizlet.data.repository.qclass.c.o(cVar, bVar.d, DefinitionKt.NO_Float_VALUE, 6);
        com.quizlet.data.repository.qclass.c.o(constrainAs.f, bVar.f, DefinitionKt.NO_Float_VALUE, 6);
        com.quizlet.data.repository.searchexplanations.c.j(constrainAs.c, bVar.c, DefinitionKt.NO_Float_VALUE, 6);
        com.quizlet.data.repository.searchexplanations.c.j(constrainAs.e, bVar.e, DefinitionKt.NO_Float_VALUE, 6);
        return Unit.a;
    }
}
