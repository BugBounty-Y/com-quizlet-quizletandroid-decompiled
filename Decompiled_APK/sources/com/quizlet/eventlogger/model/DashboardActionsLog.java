package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DashboardActionsLog extends StandardizedEventLog {

    @JsonProperty("payload")
    @NotNull
    private DashboardActionsPayload payload = new DashboardActionsPayload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class DashboardActionsPayload extends StandardizedPayloadBase {

        @JsonProperty("is_available_offline")
        private boolean availableOffline;

        @JsonProperty("reason_target_ranked")
        private String reasonTargetRanked;

        @JsonProperty("referrer")
        private String referrer;

        @JsonProperty("target_client_model_id")
        private Long targetClientModelId;

        @JsonProperty("target_depth")
        private Integer targetDepth;

        @JsonProperty("target_model_type")
        private Integer targetModelType;

        @JsonProperty("target_server_model_id")
        private Long targetServerModelId;

        public final boolean getAvailableOffline() {
            return this.availableOffline;
        }

        public final String getReasonTargetRanked() {
            return this.reasonTargetRanked;
        }

        public final String getReferrer() {
            return this.referrer;
        }

        public final Long getTargetClientModelId() {
            return this.targetClientModelId;
        }

        public final Integer getTargetDepth() {
            return this.targetDepth;
        }

        public final Integer getTargetModelType() {
            return this.targetModelType;
        }

        public final Long getTargetServerModelId() {
            return this.targetServerModelId;
        }

        public final void setAvailableOffline(boolean z) {
            this.availableOffline = z;
        }

        public final void setReasonTargetRanked(String str) {
            this.reasonTargetRanked = str;
        }

        public final void setReferrer(String str) {
            this.referrer = str;
        }

        public final void setTargetClientModelId(Long l) {
            this.targetClientModelId = l;
        }

        public final void setTargetDepth(Integer num) {
            this.targetDepth = num;
        }

        public final void setTargetModelType(Integer num) {
            this.targetModelType = num;
        }

        public final void setTargetServerModelId(Long l) {
            this.targetServerModelId = l;
        }
    }

    static {
        new Companion(null);
    }

    public DashboardActionsLog() {
        setTable(EnumC4503n.DASHBOARD_ACTIONS);
    }

    public void setPayload(@NotNull DashboardActionsPayload dashboardActionsPayload) {
        Intrinsics.checkNotNullParameter(dashboardActionsPayload, "<set-?>");
        this.payload = dashboardActionsPayload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public DashboardActionsPayload getPayload() {
        return this.payload;
    }
}
