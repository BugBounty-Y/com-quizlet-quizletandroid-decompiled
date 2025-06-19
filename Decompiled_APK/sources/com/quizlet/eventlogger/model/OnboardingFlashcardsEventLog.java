package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class OnboardingFlashcardsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

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

        @JsonProperty("onboarding_flashcards_acknowledge")
        private Boolean onboardingFlashcardsAcknowledge;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Payload) && Intrinsics.b(this.onboardingFlashcardsAcknowledge, ((Payload) obj).onboardingFlashcardsAcknowledge);
        }

        public final Boolean getOnboardingFlashcardsAcknowledge() {
            return this.onboardingFlashcardsAcknowledge;
        }

        public final int hashCode() {
            Boolean bool = this.onboardingFlashcardsAcknowledge;
            if (bool == null) {
                return 0;
            }
            return bool.hashCode();
        }

        public final void setOnboardingFlashcardsAcknowledge(Boolean bool) {
            this.onboardingFlashcardsAcknowledge = bool;
        }

        public final String toString() {
            return "Payload(onboardingFlashcardsAcknowledge=" + this.onboardingFlashcardsAcknowledge + ")";
        }

        public /* synthetic */ Payload(Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : bool);
        }

        public Payload(Boolean bool) {
            this.onboardingFlashcardsAcknowledge = bool;
        }
    }

    public OnboardingFlashcardsEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
