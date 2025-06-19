package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.paging.J0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Y y = this.k;
            androidx.work.impl.model.e eVar = y.l;
            com.quizlet.infra.legacysyncengine.datasources.n nVar = (com.quizlet.infra.legacysyncengine.datasources.n) ((C3) eVar.b).b;
            io.reactivex.rxjava3.internal.operators.observable.J jQ = nVar.c.q(C4694c.d);
            Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
            io.reactivex.rxjava3.internal.operators.observable.J jQ2 = jQ.q(new C4636c(eVar, 3));
            Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
            io.reactivex.rxjava3.internal.operators.observable.J jQ3 = jQ2.q(new com.quizlet.quizletandroid.ui.activitycenter.views.i(y, 5));
            Intrinsics.checkNotNullExpressionValue(jQ3, "map(...)");
            J0 j0 = new J0(K1.f(Y.K(jQ3, y.I)), new com.quizlet.data.interactor.folderwithcreator.b(3, 8, null));
            J j = new J(y, null);
            this.j = 1;
            if (e0.i(j0, j, this) == aVar) {
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
