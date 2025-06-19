package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.learn.data.C4553p;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ FillInTheBlankStudiableQuestion j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(FillInTheBlankStudiableQuestion fillInTheBlankStudiableQuestion, G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = fillInTheBlankStudiableQuestion;
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.k;
        DBSession dBSession = g.j1;
        if (dBSession == null) {
            Intrinsics.m("session");
            throw null;
        }
        long id = dBSession.getId();
        com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
        g.L.j(new C4553p(new ShowQuestion.FillInTheBlank(this.j, id, fVar.u, g.I(), fVar.o)));
        return Unit.a;
    }
}
