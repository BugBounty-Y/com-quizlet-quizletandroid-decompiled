package com.quizlet.eventlogger.model;

import com.amazon.device.ads.DTBMetricsConfiguration;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.generated.enums.EnumC4503n;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class EmailTrackingEventLog extends EventLog {

    @JsonProperty("payload")
    @NotNull
    private EmailTrackingPayload payload;

    @Metadata
    @Retention(RetentionPolicy.SOURCE)
    public @interface EmailAction {

        @Metadata
        public static final class Companion {
            static {
                new Companion();
            }

            private Companion() {
            }
        }
    }

    public EmailTrackingEventLog() {
        EmailTrackingPayload emailTrackingPayload = new EmailTrackingPayload();
        emailTrackingPayload.setClientOs("Android");
        emailTrackingPayload.setDeviceType(DTBMetricsConfiguration.APSMETRICS_LEVEL2_KEY);
        emailTrackingPayload.setDedupeId(UUID.randomUUID().toString());
        this.payload = emailTrackingPayload;
        setTable(EnumC4503n.EMAIL_TRACKING);
    }

    @Override // com.quizlet.eventlogger.model.EventLog
    public final void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        if (currentUserEvent != null && currentUserEvent.c) {
            this.payload.setUsername(currentUserEvent.getCurrentUser().getUsername());
            this.payload.setUid(Long.valueOf(currentUserEvent.getCurrentUser().getId()));
        }
        this.payload.setAppSessionId(appSessionId.toString());
    }

    @JsonIgnore
    @NotNull
    public final EmailTrackingPayload getPayload() {
        return this.payload;
    }

    public final void setPayload(@NotNull EmailTrackingPayload emailTrackingPayload) {
        Intrinsics.checkNotNullParameter(emailTrackingPayload, "<set-?>");
        this.payload = emailTrackingPayload;
    }
}
