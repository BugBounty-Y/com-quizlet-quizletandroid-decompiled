package com.quizlet.eventlogger.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.appsflyer.AdRevenueScheme;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ExplanationsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static ExplanationsEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1048575, null);
            payloadModifier.invoke(payload);
            ExplanationsEventLog explanationsEventLog = new ExplanationsEventLog(payload);
            explanationsEventLog.setAction(action);
            return explanationsEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("content_url")
        private String contentUrl;

        @JsonProperty("depth")
        private Integer depth;

        @JsonProperty("exercise_id")
        private String exerciseId;

        @JsonProperty("first_time_recs_shown")
        private Boolean firstTimeRecsShown;

        @JsonProperty("item_id")
        private Long itemId;

        @JsonProperty("item_type")
        private String itemType;

        @JsonProperty("media_exercise_uuid")
        private String mediaExerciseUuid;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID)
        private String modelId;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        private Integer modelType;

        @JsonProperty("numRemaining")
        private Integer numRemaining;

        @JsonProperty(AdRevenueScheme.PLACEMENT)
        private String placement;

        @JsonProperty("question_id")
        private String questionId;

        @JsonProperty("question_slug")
        private String questionSlug;

        @JsonProperty("question_uuid")
        private String questionUuid;

        @JsonProperty("client_screen_name")
        private String screenName;

        @JsonProperty("search_query")
        private String searchQuery;

        @JsonProperty("seen_count")
        private Integer seenCount;

        @JsonProperty("textbook_id")
        private Long textbookId;

        @JsonProperty("textbook_isbn")
        private String textbookIsbn;

        @JsonProperty("threshold")
        private Integer threshold;

        public Payload() {
            this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1048575, null);
        }

        public final void c(long j, String isbn, String exerciseId) {
            Intrinsics.checkNotNullParameter(isbn, "isbn");
            Intrinsics.checkNotNullParameter(exerciseId, "exerciseId");
            this.textbookId = Long.valueOf(j);
            this.textbookIsbn = isbn;
            this.exerciseId = exerciseId;
            this.mediaExerciseUuid = exerciseId;
            this.modelType = 15;
        }

        public final void d(int i, int i2, String modelId, int i3) {
            Intrinsics.checkNotNullParameter(modelId, "modelId");
            this.modelId = modelId;
            this.modelType = Integer.valueOf(i);
            this.numRemaining = Integer.valueOf(i2);
            this.threshold = Integer.valueOf(i3);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.screenName, payload.screenName) && Intrinsics.b(this.textbookIsbn, payload.textbookIsbn) && Intrinsics.b(this.textbookId, payload.textbookId) && Intrinsics.b(this.itemType, payload.itemType) && Intrinsics.b(this.itemId, payload.itemId) && Intrinsics.b(this.exerciseId, payload.exerciseId) && Intrinsics.b(this.mediaExerciseUuid, payload.mediaExerciseUuid) && Intrinsics.b(this.questionSlug, payload.questionSlug) && Intrinsics.b(this.questionId, payload.questionId) && Intrinsics.b(this.questionUuid, payload.questionUuid) && Intrinsics.b(this.contentUrl, payload.contentUrl) && Intrinsics.b(this.searchQuery, payload.searchQuery) && Intrinsics.b(this.depth, payload.depth) && Intrinsics.b(this.seenCount, payload.seenCount) && Intrinsics.b(this.placement, payload.placement) && Intrinsics.b(this.modelId, payload.modelId) && Intrinsics.b(this.modelType, payload.modelType) && Intrinsics.b(this.numRemaining, payload.numRemaining) && Intrinsics.b(this.threshold, payload.threshold) && Intrinsics.b(this.firstTimeRecsShown, payload.firstTimeRecsShown);
        }

        public final void f(String id, String slug) {
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(slug, "slug");
            this.questionId = id;
            this.questionUuid = id;
            this.questionSlug = slug;
            this.modelType = 16;
        }

        public final void g(int i, String query) {
            Intrinsics.checkNotNullParameter(query, "query");
            this.searchQuery = query;
            this.depth = Integer.valueOf(i);
        }

        public final String getContentUrl() {
            return this.contentUrl;
        }

        public final Integer getDepth() {
            return this.depth;
        }

        public final String getExerciseId() {
            return this.exerciseId;
        }

        public final Boolean getFirstTimeRecsShown() {
            return this.firstTimeRecsShown;
        }

        public final Long getItemId() {
            return this.itemId;
        }

        public final String getItemType() {
            return this.itemType;
        }

        public final String getMediaExerciseUuid() {
            return this.mediaExerciseUuid;
        }

        public final String getModelId() {
            return this.modelId;
        }

        public final Integer getModelType() {
            return this.modelType;
        }

        public final Integer getNumRemaining() {
            return this.numRemaining;
        }

        public final String getPlacement() {
            return this.placement;
        }

        public final String getQuestionId() {
            return this.questionId;
        }

        public final String getQuestionSlug() {
            return this.questionSlug;
        }

        public final String getQuestionUuid() {
            return this.questionUuid;
        }

        public final String getScreenName() {
            return this.screenName;
        }

        public final String getSearchQuery() {
            return this.searchQuery;
        }

        public final Integer getSeenCount() {
            return this.seenCount;
        }

        public final Long getTextbookId() {
            return this.textbookId;
        }

        public final String getTextbookIsbn() {
            return this.textbookIsbn;
        }

        public final Integer getThreshold() {
            return this.threshold;
        }

        public final void h(long j, Long l, String isbn, String str) {
            Intrinsics.checkNotNullParameter(isbn, "isbn");
            this.textbookId = Long.valueOf(j);
            this.textbookIsbn = isbn;
            this.itemType = str;
            this.itemId = l;
            this.modelType = 14;
        }

        public final int hashCode() {
            String str = this.screenName;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.textbookIsbn;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Long l = this.textbookId;
            int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
            String str3 = this.itemType;
            int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Long l2 = this.itemId;
            int iHashCode5 = (iHashCode4 + (l2 == null ? 0 : l2.hashCode())) * 31;
            String str4 = this.exerciseId;
            int iHashCode6 = (iHashCode5 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.mediaExerciseUuid;
            int iHashCode7 = (iHashCode6 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.questionSlug;
            int iHashCode8 = (iHashCode7 + (str6 == null ? 0 : str6.hashCode())) * 31;
            String str7 = this.questionId;
            int iHashCode9 = (iHashCode8 + (str7 == null ? 0 : str7.hashCode())) * 31;
            String str8 = this.questionUuid;
            int iHashCode10 = (iHashCode9 + (str8 == null ? 0 : str8.hashCode())) * 31;
            String str9 = this.contentUrl;
            int iHashCode11 = (iHashCode10 + (str9 == null ? 0 : str9.hashCode())) * 31;
            String str10 = this.searchQuery;
            int iHashCode12 = (iHashCode11 + (str10 == null ? 0 : str10.hashCode())) * 31;
            Integer num = this.depth;
            int iHashCode13 = (iHashCode12 + (num == null ? 0 : num.hashCode())) * 31;
            Integer num2 = this.seenCount;
            int iHashCode14 = (iHashCode13 + (num2 == null ? 0 : num2.hashCode())) * 31;
            String str11 = this.placement;
            int iHashCode15 = (iHashCode14 + (str11 == null ? 0 : str11.hashCode())) * 31;
            String str12 = this.modelId;
            int iHashCode16 = (iHashCode15 + (str12 == null ? 0 : str12.hashCode())) * 31;
            Integer num3 = this.modelType;
            int iHashCode17 = (iHashCode16 + (num3 == null ? 0 : num3.hashCode())) * 31;
            Integer num4 = this.numRemaining;
            int iHashCode18 = (iHashCode17 + (num4 == null ? 0 : num4.hashCode())) * 31;
            Integer num5 = this.threshold;
            int iHashCode19 = (iHashCode18 + (num5 == null ? 0 : num5.hashCode())) * 31;
            Boolean bool = this.firstTimeRecsShown;
            return iHashCode19 + (bool != null ? bool.hashCode() : 0);
        }

        public final void setContentUrl(String str) {
            this.contentUrl = str;
        }

        public final void setDepth(Integer num) {
            this.depth = num;
        }

        public final void setExerciseId(String str) {
            this.exerciseId = str;
        }

        public final void setFirstTimeRecsShown(Boolean bool) {
            this.firstTimeRecsShown = bool;
        }

        public final void setItemId(Long l) {
            this.itemId = l;
        }

        public final void setItemType(String str) {
            this.itemType = str;
        }

        public final void setMediaExerciseUuid(String str) {
            this.mediaExerciseUuid = str;
        }

        public final void setModelId(String str) {
            this.modelId = str;
        }

        public final void setModelType(Integer num) {
            this.modelType = num;
        }

        public final void setNumRemaining(Integer num) {
            this.numRemaining = num;
        }

        public final void setPlacement(String str) {
            this.placement = str;
        }

        public final void setQuestionId(String str) {
            this.questionId = str;
        }

        public final void setQuestionSlug(String str) {
            this.questionSlug = str;
        }

        public final void setQuestionUuid(String str) {
            this.questionUuid = str;
        }

        public final void setScreenName(String str) {
            this.screenName = str;
        }

        public final void setSearchQuery(String str) {
            this.searchQuery = str;
        }

        public final void setSeenCount(Integer num) {
            this.seenCount = num;
        }

        public final void setTextbookId(Long l) {
            this.textbookId = l;
        }

        public final void setTextbookIsbn(String str) {
            this.textbookIsbn = str;
        }

        public final void setThreshold(Integer num) {
            this.threshold = num;
        }

        public final String toString() {
            String str = this.screenName;
            String str2 = this.textbookIsbn;
            Long l = this.textbookId;
            String str3 = this.itemType;
            Long l2 = this.itemId;
            String str4 = this.exerciseId;
            String str5 = this.mediaExerciseUuid;
            String str6 = this.questionSlug;
            String str7 = this.questionId;
            String str8 = this.questionUuid;
            String str9 = this.contentUrl;
            String str10 = this.searchQuery;
            Integer num = this.depth;
            Integer num2 = this.seenCount;
            String str11 = this.placement;
            String str12 = this.modelId;
            Integer num3 = this.modelType;
            Integer num4 = this.numRemaining;
            Integer num5 = this.threshold;
            Boolean bool = this.firstTimeRecsShown;
            StringBuilder sbH = AbstractC0147y.h("Payload(screenName=", str, ", textbookIsbn=", str2, ", textbookId=");
            sbH.append(l);
            sbH.append(", itemType=");
            sbH.append(str3);
            sbH.append(", itemId=");
            sbH.append(l2);
            sbH.append(", exerciseId=");
            sbH.append(str4);
            sbH.append(", mediaExerciseUuid=");
            B.u(sbH, str5, ", questionSlug=", str6, ", questionId=");
            B.u(sbH, str7, ", questionUuid=", str8, ", contentUrl=");
            B.u(sbH, str9, ", searchQuery=", str10, ", depth=");
            sbH.append(num);
            sbH.append(", seenCount=");
            sbH.append(num2);
            sbH.append(", placement=");
            B.u(sbH, str11, ", modelId=", str12, ", modelType=");
            sbH.append(num3);
            sbH.append(", numRemaining=");
            sbH.append(num4);
            sbH.append(", threshold=");
            sbH.append(num5);
            sbH.append(", firstTimeRecsShown=");
            sbH.append(bool);
            sbH.append(")");
            return sbH.toString();
        }

        public /* synthetic */ Payload(String str, String str2, Long l, String str3, Long l2, String str4, String str5, String str6, String str7, String str8, String str9, String str10, Integer num, Integer num2, String str11, String str12, Integer num3, Integer num4, Integer num5, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : str3, (i & 16) != 0 ? null : l2, (i & 32) != 0 ? null : str4, (i & 64) != 0 ? null : str5, (i & 128) != 0 ? null : str6, (i & 256) != 0 ? null : str7, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str8, (i & 1024) != 0 ? null : str9, (i & 2048) != 0 ? null : str10, (i & 4096) != 0 ? null : num, (i & 8192) != 0 ? null : num2, (i & 16384) != 0 ? null : str11, (i & 32768) != 0 ? null : str12, (i & 65536) != 0 ? null : num3, (i & 131072) != 0 ? null : num4, (i & 262144) != 0 ? null : num5, (i & 524288) != 0 ? null : bool);
        }

        public Payload(String str, String str2, Long l, String str3, Long l2, String str4, String str5, String str6, String str7, String str8, String str9, String str10, Integer num, Integer num2, String str11, String str12, Integer num3, Integer num4, Integer num5, Boolean bool) {
            this.screenName = str;
            this.textbookIsbn = str2;
            this.textbookId = l;
            this.itemType = str3;
            this.itemId = l2;
            this.exerciseId = str4;
            this.mediaExerciseUuid = str5;
            this.questionSlug = str6;
            this.questionId = str7;
            this.questionUuid = str8;
            this.contentUrl = str9;
            this.searchQuery = str10;
            this.depth = num;
            this.seenCount = num2;
            this.placement = str11;
            this.modelId = str12;
            this.modelType = num3;
            this.numRemaining = num4;
            this.threshold = num5;
            this.firstTimeRecsShown = bool;
        }
    }

    public ExplanationsEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ExplanationsEventLog) && Intrinsics.b(this.payload, ((ExplanationsEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "ExplanationsEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
