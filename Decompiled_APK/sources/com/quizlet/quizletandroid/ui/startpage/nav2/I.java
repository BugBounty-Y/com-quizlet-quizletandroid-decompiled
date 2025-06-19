package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.paging.J0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Y y = this.k;
            androidx.work.impl.model.e eVar = y.l;
            C3 c3 = (C3) eVar.b;
            io.reactivex.rxjava3.core.i iVarM = ((com.quizlet.data.repository.explanations.myexplanations.a) c3.e).g(6, C4930v.c(com.quizlet.data.model.Y.values()), (io.reactivex.rxjava3.subjects.r) c3.k).m();
            Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
            io.reactivex.rxjava3.internal.operators.observable.J j = new io.reactivex.rxjava3.internal.operators.observable.J(iVarM, C4694c.f, 4);
            Intrinsics.checkNotNullExpressionValue(j, "onErrorResumeNext(...)");
            io.reactivex.rxjava3.internal.operators.observable.J jQ = io.reactivex.rxjava3.core.i.y(j, ((androidx.work.impl.model.c) eVar.c).t().m(), C4694c.g).q(new com.quizlet.login.authentication.login.a(eVar, 12));
            Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
            io.reactivex.rxjava3.internal.operators.observable.J jQ2 = jQ.q(new com.quizlet.quizletandroid.k(y, 10));
            Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
            J0 j0 = new J0(K1.f(Y.K(jQ2, y.D)), new com.quizlet.data.interactor.folderwithcreator.b(3, 7, null));
            H h = new H(y, null);
            this.j = 1;
            if (e0.i(j0, h, this) == aVar) {
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
