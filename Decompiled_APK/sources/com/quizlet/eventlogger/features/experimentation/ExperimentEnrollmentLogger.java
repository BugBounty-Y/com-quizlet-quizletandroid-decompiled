package com.quizlet.eventlogger.features.experimentation;

import com.quizlet.eventlogger.EventLogger;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExperimentEnrollmentLogger {

    @NotNull
    private final EventLogger eventLogger;

    public ExperimentEnrollmentLogger(@NotNull EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.eventLogger = eventLogger;
    }

    public final void a(String experiment, String treatment) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(treatment, "treatment");
        ExperimentEnrollmentLog.b.getClass();
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(treatment, "treatment");
        ExperimentEnrollmentLog experimentEnrollmentLog = new ExperimentEnrollmentLog();
        experimentEnrollmentLog.setAction("enroll");
        experimentEnrollmentLog.getPayload().setExperimentName(experiment);
        experimentEnrollmentLog.getPayload().setTreatmentName(treatment);
        this.eventLogger.l(experimentEnrollmentLog);
    }
}
