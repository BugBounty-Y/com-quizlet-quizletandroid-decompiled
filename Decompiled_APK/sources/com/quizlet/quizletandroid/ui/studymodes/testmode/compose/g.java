package com.quizlet.quizletandroid.ui.studymodes.testmode.compose;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.Y;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.A;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.AbstractC4766h;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4762d;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4763e;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4764f;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4765g;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.k, hVar);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((AbstractC4766h) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String title;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        AbstractC4766h abstractC4766h = (AbstractC4766h) this.j;
        boolean zB = Intrinsics.b(abstractC4766h, C4762d.a);
        G g = this.k;
        if (zB) {
            g.getClass();
            String strA = Y.TEST_TO_FLASHCARDS.a();
            com.quizlet.features.infra.basestudy.manager.f fVar = g.D;
            com.quizlet.features.infra.basestudy.manager.f.j(fVar, strA, 6);
            androidx.lifecycle.Y y = g.A;
            int i = fVar.q;
            DBStudySet dBStudySetE = fVar.e();
            if (dBStudySetE == null || (title = dBStudySetE.getTitle()) == null) {
                title = "";
            }
            y.j(new com.quizlet.quizletandroid.ui.studymodes.testmode.models.c(i, fVar.l, fVar.m, title, g.D()));
        } else if (abstractC4766h instanceof C4763e) {
            List missedTermIds = ((C4763e) abstractC4766h).a;
            g.getClass();
            Intrinsics.checkNotNullParameter(missedTermIds, "missedTermIds");
            com.quizlet.features.infra.basestudy.manager.f.j(g.D, Y.TEST_TO_LEARN.a(), 6);
            E.A(p0.j(g), null, null, new A(g, missedTermIds, null), 3);
        } else if (Intrinsics.b(abstractC4766h, C4765g.a)) {
            g.getClass();
            String strA2 = Y.TAKE_NEW_TEST.a();
            com.quizlet.features.infra.basestudy.manager.f fVar2 = g.D;
            com.quizlet.features.infra.basestudy.manager.f.j(fVar2, strA2, 6);
            fVar2.n(false);
            g.F = g.D();
            g.c.c(Boolean.FALSE, "selectedOnlyIntent");
            G.H(g, fVar2.g().i());
        } else {
            if (!(abstractC4766h instanceof C4764f)) {
                throw new NoWhenBranchMatchedException();
            }
            g.G(((C4764f) abstractC4766h).a, true);
        }
        return Unit.a;
    }
}
