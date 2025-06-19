package com.braze.support;

import androidx.camera.camera2.internal.C0148z;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.J;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Object d;

    public /* synthetic */ r(Object obj, long j, long j2, int i) {
        this.a = i;
        this.d = obj;
        this.b = j;
        this.c = j2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeImageUtils.calculateInSampleSize$lambda$6((H) this.d, this.b, this.c);
            default:
                com.quizlet.data.repository.progress.b bVar = (com.quizlet.data.repository.progress.b) this.d;
                com.quizlet.remote.model.progress.e eVar = (com.quizlet.remote.model.progress.e) bVar.a;
                long j = this.b;
                long j2 = this.c;
                eVar.getClass();
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((com.quizlet.remote.service.s) ((com.quizlet.login.authentication.login.a) eVar.a).b).a(j, j2, G1.SET.b()).g(com.quizlet.remote.model.progress.b.a);
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                io.reactivex.rxjava3.core.i iVarM = gVarG.g(new com.quizlet.quizletandroid.ui.setcreation.managers.n(eVar, 7)).m();
                Intrinsics.checkNotNullExpressionValue(iVarM, "toObservable(...)");
                io.reactivex.rxjava3.core.i iVarM2 = iVarM.m(new C0148z(bVar, j, j2, 7), SubsamplingScaleImageView.TILE_SIZE_AUTO);
                Intrinsics.checkNotNullExpressionValue(iVarM2, "flatMap(...)");
                J j3 = new J(iVarM2, new com.google.firebase.crashlytics.internal.common.j(bVar, 13), 4);
                Intrinsics.checkNotNullExpressionValue(j3, "onErrorResumeNext(...)");
                C4885d c4885dJ = j3.j();
                Intrinsics.checkNotNullExpressionValue(c4885dJ, "firstOrError(...)");
                return c4885dJ;
        }
    }
}
