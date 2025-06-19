package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ViewsEventLog extends StandardizedEventLog {

    @NotNull
    private static final String VISIT_LOGGING_VERSION = "1";
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final ViewsEventPayload payload = new ViewsEventPayload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static ViewsEventLog a(int i, Long l, long j, String versionName) {
            Intrinsics.checkNotNullParameter(versionName, "versionName");
            ViewsEventLog viewsEventLog = new ViewsEventLog();
            viewsEventLog.setAction("visit");
            viewsEventLog.getPayload().setAgent(null);
            viewsEventLog.getPayload().setVersion(versionName + ":1");
            viewsEventLog.getPayload().setModelType(Integer.valueOf(i));
            viewsEventLog.getPayload().setServerModelId(l);
            viewsEventLog.getPayload().setClientModelId(Long.valueOf(j));
            return viewsEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class ViewsEventPayload extends StandardizedPayloadBase {

        @JsonProperty("agent")
        private String agent;

        @JsonProperty("client_model_id")
        private Long clientModelId;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private Integer modelType;

        @JsonProperty("server_model_id")
        private Long serverModelId;

        @JsonProperty("version")
        private String version;

        public final String getAgent() {
            return this.agent;
        }

        public final Long getClientModelId() {
            return this.clientModelId;
        }

        public final Integer getModelType() {
            return this.modelType;
        }

        public final Long getServerModelId() {
            return this.serverModelId;
        }

        public final String getVersion() {
            return this.version;
        }

        public final void setAgent(String str) {
            this.agent = str;
        }

        public final void setClientModelId(Long l) {
            this.clientModelId = l;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setServerModelId(Long l) {
            this.serverModelId = l;
        }

        public final void setVersion(String str) {
            this.version = str;
        }
    }

    public ViewsEventLog() {
        setTable(EnumC4503n.VIEW_EVENTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public ViewsEventPayload getPayload() {
        return this.payload;
    }
}
