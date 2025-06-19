package com.quizlet.eventlogger.model;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.appsflyer.AdRevenueScheme;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyFunnelEventLog extends StandardizedEventLog {
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

        @JsonProperty("action")
        private String action;

        @JsonProperty("folder_id")
        private Long folderId;

        @JsonProperty("funnel_uuid")
        private String funnelID;

        @JsonProperty("item_order")
        private Integer itemOrder;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID)
        private Long modelId;

        @JsonProperty("model_id_string")
        private final String modelIdString;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private int modelType;

        @JsonProperty("note_uuid")
        private final String noteUuid;

        @JsonProperty("page_order")
        private Integer pageOrder;

        @JsonProperty(AdRevenueScheme.PLACEMENT)
        private String placement;

        @JsonProperty("recommendation_algorithm")
        private Integer recommendationAlgorithm;

        @JsonProperty("reason")
        private final String recommendationRejectionReason;

        @JsonProperty("subplacement")
        private String subplacement;

        @JsonProperty("tag")
        private String tag;

        public Payload() {
            this(null, 0, null, null, null, null, null, null, null, null, null, null, null, null, 16383, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.action, payload.action) && this.modelType == payload.modelType && Intrinsics.b(this.modelId, payload.modelId) && Intrinsics.b(this.funnelID, payload.funnelID) && Intrinsics.b(this.placement, payload.placement) && Intrinsics.b(this.subplacement, payload.subplacement) && Intrinsics.b(this.pageOrder, payload.pageOrder) && Intrinsics.b(this.itemOrder, payload.itemOrder) && Intrinsics.b(this.recommendationAlgorithm, payload.recommendationAlgorithm) && Intrinsics.b(this.recommendationRejectionReason, payload.recommendationRejectionReason) && Intrinsics.b(this.noteUuid, payload.noteUuid) && Intrinsics.b(this.modelIdString, payload.modelIdString) && Intrinsics.b(this.folderId, payload.folderId) && Intrinsics.b(this.tag, payload.tag);
        }

        public final String getAction() {
            return this.action;
        }

        public final Long getFolderId() {
            return this.folderId;
        }

        public final String getFunnelID() {
            return this.funnelID;
        }

        public final Integer getItemOrder() {
            return this.itemOrder;
        }

        public final Long getModelId() {
            return this.modelId;
        }

        public final String getModelIdString() {
            return this.modelIdString;
        }

        public final int getModelType() {
            return this.modelType;
        }

        public final String getNoteUuid() {
            return this.noteUuid;
        }

        public final Integer getPageOrder() {
            return this.pageOrder;
        }

        public final String getPlacement() {
            return this.placement;
        }

        public final Integer getRecommendationAlgorithm() {
            return this.recommendationAlgorithm;
        }

        public final String getRecommendationRejectionReason() {
            return this.recommendationRejectionReason;
        }

        public final String getSubplacement() {
            return this.subplacement;
        }

        public final String getTag() {
            return this.tag;
        }

        public final int hashCode() {
            String str = this.action;
            int iB = d0.b(this.modelType, (str == null ? 0 : str.hashCode()) * 31, 31);
            Long l = this.modelId;
            int iHashCode = (iB + (l == null ? 0 : l.hashCode())) * 31;
            String str2 = this.funnelID;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.placement;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.subplacement;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            Integer num = this.pageOrder;
            int iHashCode5 = (iHashCode4 + (num == null ? 0 : num.hashCode())) * 31;
            Integer num2 = this.itemOrder;
            int iHashCode6 = (iHashCode5 + (num2 == null ? 0 : num2.hashCode())) * 31;
            Integer num3 = this.recommendationAlgorithm;
            int iHashCode7 = (iHashCode6 + (num3 == null ? 0 : num3.hashCode())) * 31;
            String str5 = this.recommendationRejectionReason;
            int iHashCode8 = (iHashCode7 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.noteUuid;
            int iHashCode9 = (iHashCode8 + (str6 == null ? 0 : str6.hashCode())) * 31;
            String str7 = this.modelIdString;
            int iHashCode10 = (iHashCode9 + (str7 == null ? 0 : str7.hashCode())) * 31;
            Long l2 = this.folderId;
            int iHashCode11 = (iHashCode10 + (l2 == null ? 0 : l2.hashCode())) * 31;
            String str8 = this.tag;
            return iHashCode11 + (str8 != null ? str8.hashCode() : 0);
        }

        public final void setAction(String str) {
            this.action = str;
        }

        public final void setFolderId(Long l) {
            this.folderId = l;
        }

        public final void setFunnelID(String str) {
            this.funnelID = str;
        }

        public final void setItemOrder(Integer num) {
            this.itemOrder = num;
        }

        public final void setModelId(Long l) {
            this.modelId = l;
        }

        public final void setModelType(int i) {
            this.modelType = i;
        }

        public final void setPageOrder(Integer num) {
            this.pageOrder = num;
        }

        public final void setPlacement(String str) {
            this.placement = str;
        }

        public final void setRecommendationAlgorithm(Integer num) {
            this.recommendationAlgorithm = num;
        }

        public final void setSubplacement(String str) {
            this.subplacement = str;
        }

        public final void setTag(String str) {
            this.tag = str;
        }

        public final String toString() {
            String str = this.action;
            int i = this.modelType;
            Long l = this.modelId;
            String str2 = this.funnelID;
            String str3 = this.placement;
            String str4 = this.subplacement;
            Integer num = this.pageOrder;
            Integer num2 = this.itemOrder;
            Integer num3 = this.recommendationAlgorithm;
            String str5 = this.recommendationRejectionReason;
            String str6 = this.noteUuid;
            String str7 = this.modelIdString;
            Long l2 = this.folderId;
            String str8 = this.tag;
            StringBuilder sb = new StringBuilder("Payload(action=");
            sb.append(str);
            sb.append(", modelType=");
            sb.append(i);
            sb.append(", modelId=");
            sb.append(l);
            sb.append(", funnelID=");
            sb.append(str2);
            sb.append(", placement=");
            B.u(sb, str3, ", subplacement=", str4, ", pageOrder=");
            sb.append(num);
            sb.append(", itemOrder=");
            sb.append(num2);
            sb.append(", recommendationAlgorithm=");
            sb.append(num3);
            sb.append(", recommendationRejectionReason=");
            sb.append(str5);
            sb.append(", noteUuid=");
            B.u(sb, str6, ", modelIdString=", str7, ", folderId=");
            sb.append(l2);
            sb.append(", tag=");
            sb.append(str8);
            sb.append(")");
            return sb.toString();
        }

        public /* synthetic */ Payload(String str, int i, Long l, String str2, String str3, String str4, Integer num, Integer num2, Integer num3, String str5, String str6, String str7, Long l2, String str8, int i2, DefaultConstructorMarker defaultConstructorMarker) {
            this((i2 & 1) != 0 ? null : str, (i2 & 2) != 0 ? 0 : i, (i2 & 4) != 0 ? null : l, (i2 & 8) != 0 ? null : str2, (i2 & 16) != 0 ? null : str3, (i2 & 32) != 0 ? null : str4, (i2 & 64) != 0 ? null : num, (i2 & 128) != 0 ? null : num2, (i2 & 256) != 0 ? null : num3, (i2 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str5, (i2 & 1024) != 0 ? null : str6, (i2 & 2048) != 0 ? null : str7, (i2 & 4096) != 0 ? null : l2, (i2 & 8192) != 0 ? null : str8);
        }

        public Payload(String str, int i, Long l, String str2, String str3, String str4, Integer num, Integer num2, Integer num3, String str5, String str6, String str7, Long l2, String str8) {
            this.action = str;
            this.modelType = i;
            this.modelId = l;
            this.funnelID = str2;
            this.placement = str3;
            this.subplacement = str4;
            this.pageOrder = num;
            this.itemOrder = num2;
            this.recommendationAlgorithm = num3;
            this.recommendationRejectionReason = str5;
            this.noteUuid = str6;
            this.modelIdString = str7;
            this.folderId = l2;
            this.tag = str8;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public StudyFunnelEventLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudyFunnelEventLog) && Intrinsics.b(this.payload, ((StudyFunnelEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "StudyFunnelEventLog(payload=" + this.payload + ")";
    }

    public /* synthetic */ StudyFunnelEventLog(Payload payload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        Payload payload2;
        if ((i & 1) != 0) {
            payload2 = new Payload(null, 0, null, null, null, null, null, null, null, null, null, null, null, null, 16383, null);
        } else {
            payload2 = payload;
        }
        this(payload2);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }

    public StudyFunnelEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.STUDY_FUNNEL_EVENTS);
    }
}
