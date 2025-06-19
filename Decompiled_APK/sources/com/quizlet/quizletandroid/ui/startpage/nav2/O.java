package com.quizlet.quizletandroid.ui.startpage.nav2;

import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class O implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Map b;

    public /* synthetic */ O(int i, Map map) {
        this.a = i;
        this.b = map;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p pVar = (com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.p) obj;
        switch (this.a) {
            case 0:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar.getClass();
                Intrinsics.checkNotNullParameter(oVar, "<set-?>");
                pVar.f = oVar;
                break;
            default:
                com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o oVar2 = new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.o(true, this.b.isEmpty());
                pVar.getClass();
                Intrinsics.checkNotNullParameter(oVar2, "<set-?>");
                pVar.f = oVar2;
                break;
        }
        return Unit.a;
    }
}
