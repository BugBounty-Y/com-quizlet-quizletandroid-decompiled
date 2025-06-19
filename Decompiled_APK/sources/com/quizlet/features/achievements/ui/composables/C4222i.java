package com.quizlet.features.achievements.ui.composables;

import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.achievements.ui.composables.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4222i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    public /* synthetic */ C4222i(List list, int i) {
        this.a = i;
        this.b = list;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.foundation.lazy.g LazyRow = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyRow, "$this$LazyRow");
                List list = this.b;
                LazyRow.q(list.size(), null, new com.quizlet.assembly.compose.menu.e(list, 2), new androidx.compose.runtime.internal.d(true, -632812321, new l(list, 0)));
                break;
            case 1:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar.getClass();
                Intrinsics.checkNotNullParameter(oVar, "<set-?>");
                pVar.g = oVar;
                break;
            case 2:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar2 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar2 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar2.getClass();
                Intrinsics.checkNotNullParameter(oVar2, "<set-?>");
                pVar2.e = oVar2;
                break;
            case 3:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar3 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar3 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar3.getClass();
                Intrinsics.checkNotNullParameter(oVar3, "<set-?>");
                pVar3.d = oVar3;
                break;
            case 4:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar4 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar4 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar4.getClass();
                Intrinsics.checkNotNullParameter(oVar4, "<set-?>");
                pVar4.a = oVar4;
                break;
            case 5:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar5 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar5 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar5.getClass();
                Intrinsics.checkNotNullParameter(oVar5, "<set-?>");
                pVar5.c = oVar5;
                break;
            case 6:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar6 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar6 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar6.getClass();
                Intrinsics.checkNotNullParameter(oVar6, "<set-?>");
                pVar6.h = oVar6;
                break;
            default:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar7 = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar7 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar7.getClass();
                Intrinsics.checkNotNullParameter(oVar7, "<set-?>");
                pVar7.b = oVar7;
                break;
        }
        return Unit.a;
    }
}
