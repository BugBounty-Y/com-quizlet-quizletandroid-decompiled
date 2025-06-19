package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4727q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ OldHomeFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4727q(OldHomeFragment oldHomeFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oldHomeFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4727q(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4727q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            OldHomeFragment oldHomeFragment = this.k;
            C1087t c1087t = new C1087t(new com.quizlet.analytics.marketing.appsflyer.d(((com.quizlet.quizletandroid.ui.globalnav.viewmodel.e) ((com.quizlet.quizletandroid.ui.globalnav.viewmodel.h) oldHomeFragment.u.getValue())).h, 6), 6);
            C4726p c4726p = new C4726p(oldHomeFragment, null);
            this.j = 1;
            if (e0.i(c1087t, c4726p, this) == aVar) {
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
