package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4721q;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class P extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Y l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        P p = new P(this.l, hVar);
        p.k = obj;
        return p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((P) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            List<com.quizlet.quizletandroid.ui.startpage.nav2.model.C> list = (List) this.k;
            Intrinsics.d(list);
            Y y = this.l;
            y.getClass();
            ArrayList arrayList = new ArrayList();
            for (com.quizlet.quizletandroid.ui.startpage.nav2.model.C c : list) {
                Intrinsics.e(c, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.startpage.nav2.model.HorizontalSchoolCourseRecommendationStudySetHomeData");
                com.quizlet.quizletandroid.ui.startpage.nav2.model.D d = (com.quizlet.quizletandroid.ui.startpage.nav2.model.D) c;
                d.f = list.indexOf(c) + 1;
                kotlin.collections.G.u(arrayList, y.H(kotlin.collections.A.b(d)));
            }
            List data = kotlin.jvm.internal.O.b(CollectionsKt.y0(arrayList));
            Map mapE = Y.E(y, data);
            C4721q c4721q = y.t;
            c4721q.getClass();
            Intrinsics.checkNotNullParameter(data, "data");
            c4721q.f = data;
            y.l1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.u(mapE));
            O o = new O(0, mapE);
            this.j = 1;
            if (Y.C(y, o, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
