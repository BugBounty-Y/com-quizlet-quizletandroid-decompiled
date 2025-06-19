package com.quizlet.eventlogger.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.utmhelper.a;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ShareEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private final Payload payload = new Payload();

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static ShareEventLog a(a utmParams, Integer num, Long l, String sharedUrl, String str) {
            Intrinsics.checkNotNullParameter(sharedUrl, "sharedUrl");
            Intrinsics.checkNotNullParameter(utmParams, "utmParams");
            ShareEventLog shareEventLog = new ShareEventLog();
            shareEventLog.setAction("outbound");
            shareEventLog.getPayload().setServerModelId(l);
            shareEventLog.getPayload().setServerModelUuid(str);
            shareEventLog.getPayload().setModelType(num);
            shareEventLog.getPayload().setShareUrl(sharedUrl);
            shareEventLog.getPayload().setUtmCampaign(utmParams.b);
            shareEventLog.getPayload().setUtmMedium(utmParams.c);
            shareEventLog.getPayload().setUtmSource(utmParams.d);
            return shareEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private Integer modelType;

        @JsonProperty("normalized_source")
        private String normalizedSource;

        @JsonProperty("server_model_id")
        private Long serverModelId;

        @JsonProperty("server_model_uuid")
        private String serverModelUuid;

        @JsonProperty("share_url")
        private String shareUrl;

        @JsonProperty("sharer_user_id")
        private Long sharerUserId;

        @JsonProperty("utm_campaign")
        private String utmCampaign;

        @JsonProperty("utm_medium")
        private String utmMedium;

        @JsonProperty("utm_source")
        private String utmSource;

        public final Integer getModelType() {
            return this.modelType;
        }

        public final String getNormalizedSource() {
            return this.normalizedSource;
        }

        public final Long getServerModelId() {
            return this.serverModelId;
        }

        public final String getServerModelUuid() {
            return this.serverModelUuid;
        }

        public final String getShareUrl() {
            return this.shareUrl;
        }

        public final Long getSharerUserId() {
            return this.sharerUserId;
        }

        public final String getUtmCampaign() {
            return this.utmCampaign;
        }

        public final String getUtmMedium() {
            return this.utmMedium;
        }

        public final String getUtmSource() {
            return this.utmSource;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setNormalizedSource(String str) {
            this.normalizedSource = str;
        }

        public final void setServerModelId(Long l) {
            this.serverModelId = l;
        }

        public final void setServerModelUuid(String str) {
            this.serverModelUuid = str;
        }

        public final void setShareUrl(String str) {
            this.shareUrl = str;
        }

        public final void setSharerUserId(Long l) {
            this.sharerUserId = l;
        }

        public final void setUtmCampaign(String str) {
            this.utmCampaign = str;
        }

        public final void setUtmMedium(String str) {
            this.utmMedium = str;
        }

        public final void setUtmSource(String str) {
            this.utmSource = str;
        }
    }

    public ShareEventLog() {
        setTable(EnumC4503n.SHARE_EVENTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
