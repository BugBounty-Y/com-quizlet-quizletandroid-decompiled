package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.z1;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import com.quizlet.studiablemodels.StudiableWriteMasteryBuckets;
import io.reactivex.rxjava3.internal.operators.observable.C;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class d extends com.quizlet.viewmodel.b {
    public final com.quizlet.remote.model.notes.e c;
    public final Y d;
    public final Y e;
    public final X f;
    public final X g;
    public o h;
    public p i;
    public final StudiableWriteMasteryBuckets j;

    public d(m0 savedStateHandle, com.quizlet.remote.model.notes.e dataManager, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, StudyModeEventLogger.Factory studyModeEventLoggerFactory, com.quizlet.data.repository.widget.b studySessionEventManager) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataManager, "dataManager");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(studyModeEventLoggerFactory, "studyModeEventLoggerFactory");
        Intrinsics.checkNotNullParameter(studySessionEventManager, "studySessionEventManager");
        this.c = dataManager;
        Object objA = savedStateHandle.a("KEY_LEARN_CHECKPOINT_STUDYABLE_MDATA");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        Object objA2 = savedStateHandle.a("KEY_LEARN_CHECKPOINT_STUDY_EVENT_DATA");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Object objA3 = savedStateHandle.a("KEY_LEARN_CHECKPOINT_PROGRESS_DATA");
        if (objA3 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudiableTotalProgress studiableTotalProgress = (StudiableTotalProgress) objA3;
        Object objA4 = savedStateHandle.a("KEY_LEARN_CHECKPOINT_SET_TITLE");
        if (objA4 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        Object objA5 = savedStateHandle.a("KEY_LEARN_CHECKPOINT_STUDY_MODE_TYPE");
        if (objA5 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        int iIntValue = ((Number) objA5).intValue();
        Y y = new Y();
        this.d = y;
        this.e = new Y();
        this.f = new X(1);
        this.g = new X(1);
        this.h = o.a;
        K k = K.a;
        this.i = new p(k, k);
        StudiableWriteMasteryBuckets studiableWriteMasteryBuckets = studiableTotalProgress.a;
        this.j = studiableWriteMasteryBuckets;
        A1.Companion.getClass();
        Intrinsics.checkNotNullExpressionValue(studyModeEventLoggerFactory.a(z1.a(iIntValue)), "create(...)");
        int size = studiableWriteMasteryBuckets.a.size();
        int size2 = studiableWriteMasteryBuckets.b.size();
        int i = (int) studiableTotalProgress.b;
        y.j(new a(i, new n(i, this.h, size, size2)));
        dataManager.m(studyableModelData.k(), loggedInUserManager.e.getPersonId(), studyableModelData.e());
        Set setIds = studyableModelData.e();
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        J j = (J) dataManager.c;
        io.reactivex.rxjava3.internal.operators.observable.J jQ = j.d(setIds).q(new com.google.mlkit.vision.documentscanner.internal.c(dataManager, 23));
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        c cVar = new c(this, 0);
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.disposables.b bVarU = new C(jQ, cVar, bVar).u(new c(this, 1), io.reactivex.rxjava3.internal.functions.d.e, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        Intrinsics.checkNotNullParameter(bVarU, "<this>");
        A(bVarU);
        com.quizlet.features.infra.studysetting.datasource.a aVar = (com.quizlet.features.infra.studysetting.datasource.a) j.d;
        if (aVar != null) {
            aVar.d();
        }
        com.quizlet.features.infra.studysetting.datasource.a aVar2 = (com.quizlet.features.infra.studysetting.datasource.a) j.e;
        if (aVar2 != null) {
            aVar2.d();
        }
    }
}
