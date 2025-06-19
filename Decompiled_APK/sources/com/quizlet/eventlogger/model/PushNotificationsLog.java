package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class PushNotificationsLog extends StandardizedEventLog {
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

        @JsonProperty("client_model_id")
        private Long clientModelId;

        @JsonProperty("message_id")
        private String messageId;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private Integer modelType;

        @JsonProperty("notification_body")
        private String notificationBody;

        @JsonProperty("notification_type")
        private Integer notificationType;

        @JsonProperty("server_model_id")
        private Long serverModelId;

        public final Long getClientModelId() {
            return this.clientModelId;
        }

        public final String getMessageId() {
            return this.messageId;
        }

        public final Integer getModelType() {
            return this.modelType;
        }

        public final String getNotificationBody() {
            return this.notificationBody;
        }

        public final Integer getNotificationType() {
            return this.notificationType;
        }

        public final Long getServerModelId() {
            return this.serverModelId;
        }

        public final void setClientModelId(Long l) {
            this.clientModelId = l;
        }

        public final void setMessageId(String str) {
            this.messageId = str;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setNotificationBody(String str) {
            this.notificationBody = str;
        }

        public final void setNotificationType(Integer num) {
            this.notificationType = num;
        }

        public final void setServerModelId(Long l) {
            this.serverModelId = l;
        }
    }

    public PushNotificationsLog() {
        setTable(EnumC4503n.NOTIFICATION_EVENTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
