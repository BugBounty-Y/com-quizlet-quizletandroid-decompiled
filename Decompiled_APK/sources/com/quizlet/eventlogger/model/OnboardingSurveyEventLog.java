package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class OnboardingSurveyEventLog extends StandardizedEventLog {
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

        @JsonProperty("onboarding_survey_source")
        private String onboardingSurveySource;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 1, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Payload) && Intrinsics.b(this.onboardingSurveySource, ((Payload) obj).onboardingSurveySource);
        }

        public final String getOnboardingSurveySource() {
            return this.onboardingSurveySource;
        }

        public final int hashCode() {
            String str = this.onboardingSurveySource;
            if (str == null) {
                return 0;
            }
            return str.hashCode();
        }

        public final void setOnboardingSurveySource(String str) {
            this.onboardingSurveySource = str;
        }

        public final String toString() {
            return a.B("Payload(onboardingSurveySource=", this.onboardingSurveySource, ")");
        }

        public /* synthetic */ Payload(String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str);
        }

        public Payload(String str) {
            this.onboardingSurveySource = str;
        }
    }

    public OnboardingSurveyEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
