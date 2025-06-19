package com.quizlet.eventlogger.features.search;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import com.quizlet.eventlogger.model.EventLog;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.generated.enums.K0;
import java.util.Date;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchImpressionsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final SearchImpressionsPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static SearchImpressionsEventLog a(String searchSessionId, int i, String query, String modelId, int i2) {
            Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
            Intrinsics.checkNotNullParameter(query, "query");
            Intrinsics.checkNotNullParameter(modelId, "modelId");
            return new SearchImpressionsEventLog(new SearchImpressionsPayload(searchSessionId, 0L, modelId, 0, i, Integer.valueOf(i2), 0, null, null, query, null, null, 0, 5568, null));
        }

        private Companion() {
        }
    }

    public SearchImpressionsEventLog(@JsonProperty("payload") @NotNull SearchImpressionsPayload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.SEARCH_IMPRESSIONS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog, com.quizlet.eventlogger.model.EventLog
    public final void a(UUID appSessionId, UUID androidDeviceId, Boolean bool, CurrentUserEvent currentUserEvent) {
        DBUser currentUser;
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Intrinsics.checkNotNullParameter(androidDeviceId, "androidDeviceId");
        super.a(appSessionId, androidDeviceId, bool, currentUserEvent);
        getPayload().setUserName((currentUserEvent == null || (currentUser = currentUserEvent.getCurrentUser()) == null) ? null : currentUser.getUsername());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SearchImpressionsEventLog) && Intrinsics.b(this.payload, ((SearchImpressionsEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final void setVersionName(@NotNull String versionName) {
        Intrinsics.checkNotNullParameter(versionName, "versionName");
        getPayload().setVersion(versionName);
    }

    public final String toString() {
        return "SearchImpressionsEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public SearchImpressionsPayload getPayload() {
        return this.payload;
    }

    @Metadata
    public static final class SearchImpressionsPayload extends StandardizedPayloadBase {

        @NotNull
        private final Date clientTimestamp;
        private final String currentTab;
        private final long modelId;
        private final String modelIdString;
        private final Integer modelType;
        private final int pageDepth;
        private final int pageNumber;
        private final int purchasableType;
        private final String query;

        @NotNull
        private final String searchSessionId;
        private final int uid;
        private String userName;
        private String version;

        public /* synthetic */ SearchImpressionsPayload(String str, long j, String str2, int i, int i2, Integer num, int i3, Date date, String str3, String str4, String str5, String str6, int i4, int i5, DefaultConstructorMarker defaultConstructorMarker) {
            this(str, j, (i5 & 4) != 0 ? null : str2, i, i2, (i5 & 32) != 0 ? null : num, (i5 & 64) != 0 ? K0.FREE.a() : i3, (i5 & 128) != 0 ? new Date() : date, (i5 & 256) != 0 ? null : str3, (i5 & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str4, (i5 & 1024) != 0 ? null : str5, str6, (i5 & 4096) != 0 ? 0 : i4);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SearchImpressionsPayload)) {
                return false;
            }
            SearchImpressionsPayload searchImpressionsPayload = (SearchImpressionsPayload) obj;
            return Intrinsics.b(this.searchSessionId, searchImpressionsPayload.searchSessionId) && this.modelId == searchImpressionsPayload.modelId && Intrinsics.b(this.modelIdString, searchImpressionsPayload.modelIdString) && this.pageNumber == searchImpressionsPayload.pageNumber && this.pageDepth == searchImpressionsPayload.pageDepth && Intrinsics.b(this.modelType, searchImpressionsPayload.modelType) && this.purchasableType == searchImpressionsPayload.purchasableType && Intrinsics.b(this.clientTimestamp, searchImpressionsPayload.clientTimestamp) && Intrinsics.b(this.version, searchImpressionsPayload.version) && Intrinsics.b(this.query, searchImpressionsPayload.query) && Intrinsics.b(this.userName, searchImpressionsPayload.userName) && Intrinsics.b(this.currentTab, searchImpressionsPayload.currentTab) && this.uid == searchImpressionsPayload.uid;
        }

        @JsonProperty("client_timestamp")
        @JsonDeserialize(using = EventLog.DateDeserializer.class)
        @JsonSerialize(using = EventLog.DateSerializer.class)
        @NotNull
        public final Date getClientTimestamp() {
            return this.clientTimestamp;
        }

        @JsonProperty("collection_type")
        public final String getCurrentTab() {
            return this.currentTab;
        }

        public final long getModelId() {
            return this.modelId;
        }

        public final String getModelIdString() {
            return this.modelIdString;
        }

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE)
        public final Integer getModelType() {
            return this.modelType;
        }

        public final int getPageDepth() {
            return this.pageDepth;
        }

        public final int getPageNumber() {
            return this.pageNumber;
        }

        @JsonProperty("purchasable_type")
        public final int getPurchasableType() {
            return this.purchasableType;
        }

        @JsonProperty("query")
        public final String getQuery() {
            return this.query;
        }

        @NotNull
        public final String getSearchSessionId() {
            return this.searchSessionId;
        }

        @JsonProperty("uid")
        public final int getUid() {
            return this.uid;
        }

        @JsonProperty("username")
        public final String getUserName() {
            return this.userName;
        }

        @JsonProperty("version")
        public final String getVersion() {
            return this.version;
        }

        public final int hashCode() {
            int iD = d0.d(this.searchSessionId.hashCode() * 31, 31, this.modelId);
            String str = this.modelIdString;
            int iB = d0.b(this.pageDepth, d0.b(this.pageNumber, (iD + (str == null ? 0 : str.hashCode())) * 31, 31), 31);
            Integer num = this.modelType;
            int iHashCode = (this.clientTimestamp.hashCode() + d0.b(this.purchasableType, (iB + (num == null ? 0 : num.hashCode())) * 31, 31)) * 31;
            String str2 = this.version;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.query;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.userName;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.currentTab;
            return Integer.hashCode(this.uid) + ((iHashCode4 + (str5 != null ? str5.hashCode() : 0)) * 31);
        }

        public final void setUserName(String str) {
            this.userName = str;
        }

        public final void setVersion(String str) {
            this.version = str;
        }

        public final String toString() {
            String str = this.searchSessionId;
            long j = this.modelId;
            String str2 = this.modelIdString;
            int i = this.pageNumber;
            int i2 = this.pageDepth;
            Integer num = this.modelType;
            int i3 = this.purchasableType;
            Date date = this.clientTimestamp;
            String str3 = this.version;
            String str4 = this.query;
            String str5 = this.userName;
            String str6 = this.currentTab;
            int i4 = this.uid;
            StringBuilder sb = new StringBuilder("SearchImpressionsPayload(searchSessionId=");
            sb.append(str);
            sb.append(", modelId=");
            sb.append(j);
            sb.append(", modelIdString=");
            sb.append(str2);
            sb.append(", pageNumber=");
            sb.append(i);
            sb.append(", pageDepth=");
            sb.append(i2);
            sb.append(", modelType=");
            sb.append(num);
            sb.append(", purchasableType=");
            sb.append(i3);
            sb.append(", clientTimestamp=");
            sb.append(date);
            B.u(sb, ", version=", str3, ", query=", str4);
            B.u(sb, ", userName=", str5, ", currentTab=", str6);
            sb.append(", uid=");
            sb.append(i4);
            sb.append(")");
            return sb.toString();
        }

        public SearchImpressionsPayload(@JsonProperty("search_session_id") @NotNull String searchSessionId, @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID) long j, @JsonProperty("model_id_string") String str, @JsonProperty("page_number") int i, @JsonProperty("page_depth") int i2, Integer num, int i3, @NotNull Date clientTimestamp, String str2, String str3, String str4, String str5, int i4) {
            Intrinsics.checkNotNullParameter(searchSessionId, "searchSessionId");
            Intrinsics.checkNotNullParameter(clientTimestamp, "clientTimestamp");
            this.searchSessionId = searchSessionId;
            this.modelId = j;
            this.modelIdString = str;
            this.pageNumber = i;
            this.pageDepth = i2;
            this.modelType = num;
            this.purchasableType = i3;
            this.clientTimestamp = clientTimestamp;
            this.version = str2;
            this.query = str3;
            this.userName = str4;
            this.currentTab = str5;
            this.uid = i4;
        }
    }
}
