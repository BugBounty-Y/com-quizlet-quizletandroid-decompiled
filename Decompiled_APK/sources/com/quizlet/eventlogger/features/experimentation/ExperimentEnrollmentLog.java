package com.quizlet.eventlogger.features.experimentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExperimentEnrollmentLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final Payload payload = new Payload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("experiment_name")
        private String experimentName;

        @JsonProperty("treatment_name")
        private String treatmentName;

        public final String getExperimentName() {
            return this.experimentName;
        }

        public final String getTreatmentName() {
            return this.treatmentName;
        }

        public final void setExperimentName(String str) {
            this.experimentName = str;
        }

        public final void setTreatmentName(String str) {
            this.treatmentName = str;
        }
    }

    public ExperimentEnrollmentLog() {
        setTable(EnumC4503n.EXPERIMENT_ENROLLMENTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
