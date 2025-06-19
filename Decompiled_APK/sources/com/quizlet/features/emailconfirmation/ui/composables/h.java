package com.quizlet.features.emailconfirmation.ui.composables;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h implements Function1 {
    public static final h b = new h(0);
    public static final h c = new h(1);
    public static final h d = new h(2);
    public final /* synthetic */ int a;

    public /* synthetic */ h(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.constraintlayout.compose.a constrainAs = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c.o(constrainAs.f, constrainAs.b.f, DefinitionKt.NO_Float_VALUE, 6);
                break;
            case 1:
                androidx.constraintlayout.compose.a constrainAs2 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs2, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar = constrainAs2.d;
                androidx.constraintlayout.compose.b bVar = constrainAs2.b;
                com.quizlet.data.repository.qclass.c.o(cVar, bVar.d, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs2.e, bVar.e, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.qclass.c.o(constrainAs2.f, bVar.f, DefinitionKt.NO_Float_VALUE, 6);
                break;
            case 2:
                androidx.constraintlayout.compose.a constrainAs3 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs3, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c.o(constrainAs3.f, constrainAs3.b.f, DefinitionKt.NO_Float_VALUE, 6);
                break;
            default:
                androidx.constraintlayout.compose.a constrainAs4 = (androidx.constraintlayout.compose.a) obj;
                Intrinsics.checkNotNullParameter(constrainAs4, "$this$constrainAs");
                com.quizlet.data.repository.qclass.c cVar2 = constrainAs4.f;
                androidx.constraintlayout.compose.b bVar2 = constrainAs4.b;
                androidx.constraintlayout.compose.c cVar3 = bVar2.f;
                com.quizlet.themes.m.g.p();
                com.quizlet.data.repository.qclass.c.o(cVar2, cVar3, com.quizlet.ui.resources.designsystem.generated.j.j, 4);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs4.c, bVar2.c, DefinitionKt.NO_Float_VALUE, 6);
                com.quizlet.data.repository.searchexplanations.c.j(constrainAs4.e, bVar2.e, DefinitionKt.NO_Float_VALUE, 6);
                break;
        }
        return Unit.a;
    }
}
