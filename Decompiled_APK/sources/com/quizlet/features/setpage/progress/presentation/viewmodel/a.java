package com.quizlet.features.setpage.progress.presentation.viewmodel;

import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.features.flashcards.creatormarketing.h;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.data.repository.explanations.exercise.b;
import com.quizlet.data.repository.set.f;
import com.quizlet.data.repository.user.e;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.generated.enums.A1;
import com.quizlet.infra.legacysyncengine.net.c;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.subjects.d;
import io.reactivex.rxjava3.subjects.r;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends com.quizlet.viewmodel.a {
    public final h d;
    public final f e;
    public final long f;
    public final SetPagePerformanceLogger g;
    public final Y h;
    public final long i;
    public final e j;

    public a(m0 savedStateHandle, com.quizlet.data.repository.user.a dataProviderFactory, h logger, f progressResetUseCase, long j, SetPagePerformanceLogger setPagePerformanceLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataProviderFactory, "dataProviderFactory");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(progressResetUseCase, "progressResetUseCase");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        this.d = logger;
        this.e = progressResetUseCase;
        this.f = j;
        this.g = setPagePerformanceLogger;
        this.h = new Y();
        Long l = (Long) savedStateHandle.a("setId");
        long jLongValue = l != null ? l.longValue() : 0L;
        this.i = jLongValue;
        com.quizlet.data.interactor.school.e eVar = (com.quizlet.data.interactor.school.e) dataProviderFactory.b;
        com.quizlet.features.infra.studysetting.datasource.a aVar = new com.quizlet.features.infra.studysetting.datasource.a((c) eVar.b, jLongValue, eVar.a, (A1) null);
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = new com.quizlet.features.infra.studysetting.datasource.a((c) eVar.b, Z.b(Long.valueOf(jLongValue)));
        b bVar = new b((com.quizlet.data.interactor.progress.c) eVar.c, eVar.a, jLongValue);
        com.quizlet.shared.usecase.folderstudymaterials.c cVar = (com.quizlet.shared.usecase.folderstudymaterials.c) dataProviderFactory.c;
        o oVar = (o) dataProviderFactory.d;
        e eVar2 = new e(aVar, aVar2, bVar, cVar, oVar);
        this.j = eVar2;
        C4887f source1 = new C4887f(aVar.f(), 1);
        Intrinsics.checkNotNullExpressionValue(source1, "distinctUntilChanged(...)");
        C4887f source2 = new C4887f(aVar2.f(), 1);
        Intrinsics.checkNotNullExpressionValue(source2, "distinctUntilChanged(...)");
        i iVar = (i) bVar.d;
        iVar.getClass();
        C4887f source3 = new C4887f(iVar, 1);
        Intrinsics.checkNotNullExpressionValue(source3, "distinctUntilChanged(...)");
        Intrinsics.checkNotNullParameter(source1, "source1");
        Intrinsics.checkNotNullParameter(source2, "source2");
        Intrinsics.checkNotNullParameter(source3, "source3");
        i iVarE = i.e(source1, source2, source3, io.reactivex.rxjava3.kotlin.a.c);
        Intrinsics.checkNotNullExpressionValue(iVarE, "Observable.combineLatest… -> Triple(t1, t2, t3) })");
        C4887f c4887f = new C4887f(iVarE.s(oVar).q(new com.lyft.android.scissors.b(eVar2, 18)), 1);
        Intrinsics.checkNotNullExpressionValue(c4887f, "distinctUntilChanged(...)");
        io.reactivex.rxjava3.internal.observers.h hVarD = B7.d(c4887f, new G(1, timber.log.c.a, timber.log.a.class, "e", "e(Ljava/lang/Throwable;)V", 0, 27), null, new J(this, 14), 2);
        Intrinsics.checkNotNullParameter(hVarD, "<this>");
        A(hVarD);
    }

    @Override // com.quizlet.viewmodel.a, com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        e eVar = this.j;
        ((com.quizlet.features.infra.studysetting.datasource.a) eVar.b).g();
        ((com.quizlet.features.infra.studysetting.datasource.a) eVar.c).g();
        b bVar = (b) eVar.d;
        ((d) bVar.c).onComplete();
        ((r) bVar.b).onSuccess(Unit.a);
    }
}
