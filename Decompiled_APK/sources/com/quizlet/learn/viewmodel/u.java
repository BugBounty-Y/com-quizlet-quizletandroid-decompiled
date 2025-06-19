package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.user.LoggedInRequiredException;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.generated.enums.EnumC4467b;
import com.quizlet.generated.enums.EnumC4491j;
import com.quizlet.studiablemodels.StudiableTaskTotalProgress;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new u(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            G g = this.k;
            androidx.compose.foundation.text.input.internal.u uVar = g.y;
            StudiableTaskTotalProgress studiableTaskTotalProgressL = g.L();
            EnumC4467b enumC4467b = (studiableTaskTotalProgressL == null || studiableTaskTotalProgressL.a != 100.0d) ? EnumC4467b.COMPLETE_ROUND : EnumC4467b.REACH_END;
            this.j = 1;
            if (!((UserInfoCache) uVar.c).b()) {
                throw new LoggedInRequiredException();
            }
            Object objH = ((com.quizlet.data.repository.achievements.h) uVar.b).h(EnumC4491j.LEARN_MODE, enumC4467b, null, this);
            if (objH != aVar) {
                objH = Unit.a;
            }
            if (objH == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
