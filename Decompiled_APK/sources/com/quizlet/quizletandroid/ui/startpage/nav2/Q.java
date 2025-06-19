package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.paging.J0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import io.reactivex.rxjava3.internal.operators.observable.C4902v;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class Q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new Q(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            com.quizlet.data.interactor.set.c cVar = (com.quizlet.data.interactor.set.c) c3.d;
            io.reactivex.rxjava3.subjects.r stopToken = (io.reactivex.rxjava3.subjects.r) c3.k;
            Intrinsics.checkNotNullParameter(stopToken, "stopToken");
            io.reactivex.rxjava3.internal.operators.completable.m mVar = new io.reactivex.rxjava3.internal.operators.completable.m(((androidx.work.impl.model.c) cVar.b).c(stopToken, new com.quizlet.data.interactor.set.a(cVar, 0)), new com.quizlet.data.interactor.set.b(cVar, 0), null, 2);
            Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
            io.reactivex.rxjava3.core.i iVarM = mVar.g(C4694c.e).m();
            Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
            C4902v c4902vH = iVarM.q(new com.quizlet.quizletandroid.ui.setcreation.managers.n(eVar, 2)).h(2000L, TimeUnit.MILLISECONDS, io.reactivex.rxjava3.schedulers.e.b);
            Intrinsics.checkNotNullExpressionValue(c4902vH, "debounce(...)");
            C4905y c4905y = new C4905y(new io.reactivex.rxjava3.internal.operators.observable.C(c4902vH, new N(y, 0), io.reactivex.rxjava3.internal.functions.d.c), new N(y, 1), 0);
            Intrinsics.checkNotNullExpressionValue(c4905y, "doAfterNext(...)");
            J0 j0 = new J0(K1.f(c4905y), new com.quizlet.data.interactor.folderwithcreator.b(3, 9, null));
            P p = new P(y, null);
            this.j = 1;
            if (e0.i(j0, p, this) == aVar) {
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
