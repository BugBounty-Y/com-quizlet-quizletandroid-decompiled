package com.quizlet.learn.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.quizlet.eventlogger.features.learn.LearnEventAction;
import com.quizlet.eventlogger.features.learn.LearnEventLog;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.L;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableMeteringData;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.learn.viewmodel.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4556c extends com.quizlet.viewmodel.b {
    public final androidx.work.impl.model.c c;
    public final com.quizlet.learn.logging.d d;
    public final StudyableModelData e;
    public final StudiableMeteringData f;
    public final AssistantCheckpointProgressState g;
    public final s0 h;
    public final X i;

    public C4556c(m0 savedStateHandle, com.quizlet.learn.logging.a eventLogger, androidx.work.impl.model.c userProperties, com.quizlet.learn.logging.d postCompletionLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(postCompletionLogger, "postCompletionLogger");
        this.c = userProperties;
        this.d = postCompletionLogger;
        Object objA = savedStateHandle.a("STUDYABLE_MODEL_DATA_KEY");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        StudyableModelData studyableModelData = (StudyableModelData) objA;
        this.e = studyableModelData;
        this.f = (StudiableMeteringData) savedStateHandle.a("METERING_DATA_KEY");
        Object objA2 = savedStateHandle.a("ASSISTANT_CHECKPOINT_PROGRESS_STATE");
        if (objA2 == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = (AssistantCheckpointProgressState) objA2;
        this.h = e0.c(com.quizlet.learn.data.z.a);
        this.i = new X(1);
        eventLogger.a(LearnEventLog.Companion.c(LearnEventLog.b, LearnEventAction.c, null, L.TASK_SEQUENCE_COMPLETION_CHECKPOINT_NON_PLUS, studyableModelData.k(), null, 78));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4555b(this, null), 3);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4554a(this, null), 3);
    }
}
