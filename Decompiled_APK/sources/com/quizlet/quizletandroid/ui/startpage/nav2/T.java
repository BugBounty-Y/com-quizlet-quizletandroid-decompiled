package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.paging.J0;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_camera.K1;
import io.reactivex.rxjava3.internal.operators.observable.C4902v;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class T extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Y k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new T(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            io.reactivex.rxjava3.internal.operators.observable.J jQ = K1.g(((com.quizlet.quizletandroid.interactor.m) c3.a).b()).q(new C4694c(c3));
            Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
            C4902v c4902vH = jQ.q(new com.quizlet.login.common.interactors.d(eVar, 9)).h(2000L, TimeUnit.MILLISECONDS, io.reactivex.rxjava3.schedulers.e.b);
            Intrinsics.checkNotNullExpressionValue(c4902vH, "debounce(...)");
            io.reactivex.rxjava3.internal.operators.observable.J jQ2 = c4902vH.q(new com.quizlet.local.ormlite.models.term.b(y, 12));
            Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
            J0 j0 = new J0(K1.f(Y.K(jQ2, y.E)), new com.quizlet.data.interactor.folderwithcreator.b(3, 10, null));
            S s = new S(y, null);
            this.j = 1;
            if (e0.i(j0, s, this) == aVar) {
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
