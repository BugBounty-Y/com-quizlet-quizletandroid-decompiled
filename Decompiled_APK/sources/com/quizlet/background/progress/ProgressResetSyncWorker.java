package com.quizlet.background.progress;

import android.content.Context;
import androidx.camera.camera2.internal.C0148z;
import androidx.work.C1446u;
import androidx.work.WorkerParameters;
import androidx.work.rxjava3.RxWorker;
import androidx.work.x;
import com.google.firebase.components.n;
import com.quizlet.data.interactor.progress.e;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.completable.m;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import io.reactivex.rxjava3.internal.operators.observable.L;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ProgressResetSyncWorker extends RxWorker {
    public final WorkerParameters f;
    public final e g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ProgressResetSyncWorker(@NotNull Context context, @NotNull WorkerParameters workerParams, @NotNull e syncProgressResetUseCase) {
        super(context, workerParams);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(workerParams, "workerParams");
        Intrinsics.checkNotNullParameter(syncProgressResetUseCase, "syncProgressResetUseCase");
        this.f = workerParams;
        this.g = syncProgressResetUseCase;
    }

    @Override // androidx.work.rxjava3.RxWorker
    public final p a() {
        WorkerParameters workerParameters = this.f;
        long jB = workerParameters.b.b("personId");
        long jB2 = workerParameters.b.b("setId");
        if (jB < 0 || jB2 < 0) {
            b bVarF = p.f(new C1446u());
            Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
            return bVarF;
        }
        e eVar = this.g;
        L l = new L(eVar.b.i(jB, jB2), new C0148z(eVar, jB, jB2, 6));
        Intrinsics.checkNotNullExpressionValue(l, "flatMapCompletable(...)");
        m mVar = new m(new m(l, null, x.a(), 0), new n(29), null, 2);
        Intrinsics.checkNotNullExpressionValue(mVar, "onErrorReturn(...)");
        return mVar;
    }
}
