package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class NotificationDeviceStatusLog extends StandardizedEventLog {
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

        @JsonProperty("notification_status_extra_info")
        private String extraInfo;

        @JsonProperty("notification_system_authorization_status")
        private Integer status;

        public final String getExtraInfo() {
            return this.extraInfo;
        }

        public final Integer getStatus() {
            return this.status;
        }

        public final void setExtraInfo(String str) {
            this.extraInfo = str;
        }

        public final void setStatus(Integer num) {
            this.status = num;
        }
    }

    @Metadata
    public static final class StatusExtraInfo {

        @JsonProperty("channels")
        private Map<String, Boolean> channels;

        public final Map<String, Boolean> getChannels() {
            return this.channels;
        }

        public final void setChannels(Map<String, Boolean> map) {
            this.channels = map;
        }
    }

    public NotificationDeviceStatusLog() {
        setTable(EnumC4503n.NOTIFICATION_DEVICE_STATUS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
