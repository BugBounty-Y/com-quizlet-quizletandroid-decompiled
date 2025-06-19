package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class OnboardingELLEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static OnboardingELLEventLog a(Companion companion, String action) {
            companion.getClass();
            Intrinsics.checkNotNullParameter(action, "action");
            OnboardingELLEventLog onboardingELLEventLog = new OnboardingELLEventLog(new Payload(null, 1, 0 == true ? 1 : 0));
            onboardingELLEventLog.setAction(action);
            return onboardingELLEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("onboarding_ell_exams")
        private List<String> onboardingELLExams;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Payload) && Intrinsics.b(this.onboardingELLExams, ((Payload) obj).onboardingELLExams);
        }

        public final List<String> getOnboardingELLExams() {
            return this.onboardingELLExams;
        }

        public final int hashCode() {
            List<String> list = this.onboardingELLExams;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final void setOnboardingELLExams(List<String> list) {
            this.onboardingELLExams = list;
        }

        public final String toString() {
            return "Payload(onboardingELLExams=" + this.onboardingELLExams + ")";
        }

        public /* synthetic */ Payload(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : list);
        }

        public Payload(List<String> list) {
            this.onboardingELLExams = list;
        }
    }

    public OnboardingELLEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
