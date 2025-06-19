package com.quizlet.eventlogger.model;

import androidx.compose.ui.node.B;
import assistantMode.refactored.a;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBStudySettingFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.generated.enums.G1;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class StudyEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private Payload payload = new Payload(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 524287, null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static StudyEventLog a(String action, String studySessionId, A1 modeType, Long l, Long l2, Long l3, long j, G1 studyableType, boolean z, Integer num, String str, UUID uuid, String str2, String str3, Boolean bool, Boolean bool2) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(modeType, "modeType");
            Intrinsics.checkNotNullParameter(studyableType, "studyableType");
            StudyEventLog studyEventLog = new StudyEventLog();
            studyEventLog.setAction(action);
            studyEventLog.setPayload(new Payload(studySessionId, Integer.valueOf(modeType.a()), l, l2, l3, Long.valueOf(j), Integer.valueOf(studyableType.b()), Boolean.valueOf(z), num, null, null, null, null, str, uuid != null ? uuid.toString() : null, str2, str3, bool, bool2));
            return studyEventLog;
        }

        public static /* synthetic */ StudyEventLog b(Companion companion, String str, String str2, A1 a1, Long l, Long l2, Long l3, long j, G1 g1, boolean z, Integer num, String str3, UUID uuid, String str4, String str5, Boolean bool, int i) {
            Boolean bool2 = (i & 262144) != 0 ? null : bool;
            companion.getClass();
            return a(str, str2, a1, l, l2, l3, j, g1, z, num, str3, uuid, str4, str5, bool2, null);
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("client_session_id")
        private Long clientSessionId;

        @JsonProperty("client_studyable_id")
        private Long clientStudyableId;

        @JsonProperty("client_term_id")
        private Integer clientTermId;

        @JsonProperty("duration_seconds")
        private Integer durationSeconds;

        @JsonProperty("embed_type")
        private String embedType;

        @JsonProperty("funnel_uuid")
        private String funnelID;

        @JsonProperty("mode_type")
        private Integer modeType;

        @JsonProperty("next_action")
        private String nextAction;

        @JsonProperty("referrer")
        private String referrer;

        @JsonProperty("selected_only")
        private Boolean selectedTermsOnly;

        @JsonProperty("server_session_id")
        private Long serverSessionId;

        @JsonProperty("server_studyable_id")
        private Long serverStudyableId;

        @JsonProperty("server_term_id")
        private Integer serverTermId;

        @JsonProperty("sorting_enabled")
        private Boolean sortingEnabled;

        @JsonProperty("source")
        private Integer source;

        @JsonProperty("srs_review")
        private Boolean srsReview;

        @JsonProperty("screen")
        private String studyModeScreen;

        @JsonProperty("study_session_id")
        private String studySessionId;

        @JsonProperty(DBStudySettingFields.Names.STUDYABLE_TYPE)
        private Integer studyableType;

        public Payload() {
            this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 524287, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.studySessionId, payload.studySessionId) && Intrinsics.b(this.modeType, payload.modeType) && Intrinsics.b(this.serverSessionId, payload.serverSessionId) && Intrinsics.b(this.clientSessionId, payload.clientSessionId) && Intrinsics.b(this.serverStudyableId, payload.serverStudyableId) && Intrinsics.b(this.clientStudyableId, payload.clientStudyableId) && Intrinsics.b(this.studyableType, payload.studyableType) && Intrinsics.b(this.selectedTermsOnly, payload.selectedTermsOnly) && Intrinsics.b(this.source, payload.source) && Intrinsics.b(this.referrer, payload.referrer) && Intrinsics.b(this.durationSeconds, payload.durationSeconds) && Intrinsics.b(this.serverTermId, payload.serverTermId) && Intrinsics.b(this.clientTermId, payload.clientTermId) && Intrinsics.b(this.studyModeScreen, payload.studyModeScreen) && Intrinsics.b(this.funnelID, payload.funnelID) && Intrinsics.b(this.embedType, payload.embedType) && Intrinsics.b(this.nextAction, payload.nextAction) && Intrinsics.b(this.srsReview, payload.srsReview) && Intrinsics.b(this.sortingEnabled, payload.sortingEnabled);
        }

        public final Long getClientSessionId() {
            return this.clientSessionId;
        }

        public final Long getClientStudyableId() {
            return this.clientStudyableId;
        }

        public final Integer getClientTermId() {
            return this.clientTermId;
        }

        public final Integer getDurationSeconds() {
            return this.durationSeconds;
        }

        public final String getEmbedType() {
            return this.embedType;
        }

        public final String getFunnelID() {
            return this.funnelID;
        }

        public final Integer getModeType() {
            return this.modeType;
        }

        public final String getNextAction() {
            return this.nextAction;
        }

        public final String getReferrer() {
            return this.referrer;
        }

        public final Boolean getSelectedTermsOnly() {
            return this.selectedTermsOnly;
        }

        public final Long getServerSessionId() {
            return this.serverSessionId;
        }

        public final Long getServerStudyableId() {
            return this.serverStudyableId;
        }

        public final Integer getServerTermId() {
            return this.serverTermId;
        }

        public final Boolean getSortingEnabled() {
            return this.sortingEnabled;
        }

        public final Integer getSource() {
            return this.source;
        }

        public final Boolean getSrsReview() {
            return this.srsReview;
        }

        public final String getStudyModeScreen() {
            return this.studyModeScreen;
        }

        public final String getStudySessionId() {
            return this.studySessionId;
        }

        public final Integer getStudyableType() {
            return this.studyableType;
        }

        public final int hashCode() {
            String str = this.studySessionId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Integer num = this.modeType;
            int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
            Long l = this.serverSessionId;
            int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
            Long l2 = this.clientSessionId;
            int iHashCode4 = (iHashCode3 + (l2 == null ? 0 : l2.hashCode())) * 31;
            Long l3 = this.serverStudyableId;
            int iHashCode5 = (iHashCode4 + (l3 == null ? 0 : l3.hashCode())) * 31;
            Long l4 = this.clientStudyableId;
            int iHashCode6 = (iHashCode5 + (l4 == null ? 0 : l4.hashCode())) * 31;
            Integer num2 = this.studyableType;
            int iHashCode7 = (iHashCode6 + (num2 == null ? 0 : num2.hashCode())) * 31;
            Boolean bool = this.selectedTermsOnly;
            int iHashCode8 = (iHashCode7 + (bool == null ? 0 : bool.hashCode())) * 31;
            Integer num3 = this.source;
            int iHashCode9 = (iHashCode8 + (num3 == null ? 0 : num3.hashCode())) * 31;
            String str2 = this.referrer;
            int iHashCode10 = (iHashCode9 + (str2 == null ? 0 : str2.hashCode())) * 31;
            Integer num4 = this.durationSeconds;
            int iHashCode11 = (iHashCode10 + (num4 == null ? 0 : num4.hashCode())) * 31;
            Integer num5 = this.serverTermId;
            int iHashCode12 = (iHashCode11 + (num5 == null ? 0 : num5.hashCode())) * 31;
            Integer num6 = this.clientTermId;
            int iHashCode13 = (iHashCode12 + (num6 == null ? 0 : num6.hashCode())) * 31;
            String str3 = this.studyModeScreen;
            int iHashCode14 = (iHashCode13 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.funnelID;
            int iHashCode15 = (iHashCode14 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.embedType;
            int iHashCode16 = (iHashCode15 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.nextAction;
            int iHashCode17 = (iHashCode16 + (str6 == null ? 0 : str6.hashCode())) * 31;
            Boolean bool2 = this.srsReview;
            int iHashCode18 = (iHashCode17 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
            Boolean bool3 = this.sortingEnabled;
            return iHashCode18 + (bool3 != null ? bool3.hashCode() : 0);
        }

        public final void setClientSessionId(Long l) {
            this.clientSessionId = l;
        }

        public final void setClientStudyableId(Long l) {
            this.clientStudyableId = l;
        }

        public final void setClientTermId(Integer num) {
            this.clientTermId = num;
        }

        public final void setDurationSeconds(Integer num) {
            this.durationSeconds = num;
        }

        public final void setEmbedType(String str) {
            this.embedType = str;
        }

        public final void setFunnelID(String str) {
            this.funnelID = str;
        }

        public final void setModeType(Integer num) {
            this.modeType = num;
        }

        public final void setNextAction(String str) {
            this.nextAction = str;
        }

        public final void setReferrer(String str) {
            this.referrer = str;
        }

        public final void setSelectedTermsOnly(Boolean bool) {
            this.selectedTermsOnly = bool;
        }

        public final void setServerSessionId(Long l) {
            this.serverSessionId = l;
        }

        public final void setServerStudyableId(Long l) {
            this.serverStudyableId = l;
        }

        public final void setServerTermId(Integer num) {
            this.serverTermId = num;
        }

        public final void setSortingEnabled(Boolean bool) {
            this.sortingEnabled = bool;
        }

        public final void setSource(Integer num) {
            this.source = num;
        }

        public final void setSrsReview(Boolean bool) {
            this.srsReview = bool;
        }

        public final void setStudyModeScreen(String str) {
            this.studyModeScreen = str;
        }

        public final void setStudySessionId(String str) {
            this.studySessionId = str;
        }

        public final void setStudyableType(Integer num) {
            this.studyableType = num;
        }

        public final String toString() {
            String str = this.studySessionId;
            Integer num = this.modeType;
            Long l = this.serverSessionId;
            Long l2 = this.clientSessionId;
            Long l3 = this.serverStudyableId;
            Long l4 = this.clientStudyableId;
            Integer num2 = this.studyableType;
            Boolean bool = this.selectedTermsOnly;
            Integer num3 = this.source;
            String str2 = this.referrer;
            Integer num4 = this.durationSeconds;
            Integer num5 = this.serverTermId;
            Integer num6 = this.clientTermId;
            String str3 = this.studyModeScreen;
            String str4 = this.funnelID;
            String str5 = this.embedType;
            String str6 = this.nextAction;
            Boolean bool2 = this.srsReview;
            Boolean bool3 = this.sortingEnabled;
            StringBuilder sb = new StringBuilder("Payload(studySessionId=");
            sb.append(str);
            sb.append(", modeType=");
            sb.append(num);
            sb.append(", serverSessionId=");
            sb.append(l);
            sb.append(", clientSessionId=");
            sb.append(l2);
            sb.append(", serverStudyableId=");
            sb.append(l3);
            sb.append(", clientStudyableId=");
            sb.append(l4);
            sb.append(", studyableType=");
            sb.append(num2);
            sb.append(", selectedTermsOnly=");
            sb.append(bool);
            sb.append(", source=");
            sb.append(num3);
            sb.append(", referrer=");
            sb.append(str2);
            sb.append(", durationSeconds=");
            sb.append(num4);
            sb.append(", serverTermId=");
            sb.append(num5);
            sb.append(", clientTermId=");
            sb.append(num6);
            sb.append(", studyModeScreen=");
            sb.append(str3);
            sb.append(", funnelID=");
            B.u(sb, str4, ", embedType=", str5, ", nextAction=");
            sb.append(str6);
            sb.append(", srsReview=");
            sb.append(bool2);
            sb.append(", sortingEnabled=");
            return a.k(sb, bool3, ")");
        }

        public /* synthetic */ Payload(String str, Integer num, Long l, Long l2, Long l3, Long l4, Integer num2, Boolean bool, Integer num3, String str2, Integer num4, Integer num5, Integer num6, String str3, String str4, String str5, String str6, Boolean bool2, Boolean bool3, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : num, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : l2, (i & 16) != 0 ? null : l3, (i & 32) != 0 ? null : l4, (i & 64) != 0 ? null : num2, (i & 128) != 0 ? null : bool, (i & 256) != 0 ? null : num3, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : str2, (i & 1024) != 0 ? null : num4, (i & 2048) != 0 ? null : num5, (i & 4096) != 0 ? null : num6, (i & 8192) != 0 ? null : str3, (i & 16384) != 0 ? null : str4, (i & 32768) != 0 ? null : str5, (i & 65536) != 0 ? null : str6, (i & 131072) != 0 ? null : bool2, (i & 262144) != 0 ? null : bool3);
        }

        public Payload(String str, Integer num, Long l, Long l2, Long l3, Long l4, Integer num2, Boolean bool, Integer num3, String str2, Integer num4, Integer num5, Integer num6, String str3, String str4, String str5, String str6, Boolean bool2, Boolean bool3) {
            this.studySessionId = str;
            this.modeType = num;
            this.serverSessionId = l;
            this.clientSessionId = l2;
            this.serverStudyableId = l3;
            this.clientStudyableId = l4;
            this.studyableType = num2;
            this.selectedTermsOnly = bool;
            this.source = num3;
            this.referrer = str2;
            this.durationSeconds = num4;
            this.serverTermId = num5;
            this.clientTermId = num6;
            this.studyModeScreen = str3;
            this.funnelID = str4;
            this.embedType = str5;
            this.nextAction = str6;
            this.srsReview = bool2;
            this.sortingEnabled = bool3;
        }
    }

    public StudyEventLog() {
        setTable(EnumC4503n.STUDY_EVENTS);
    }

    public static final StudyEventLog c(String action, String studySessionId, A1 modeType, Long l, Long l2, Long l3, long j, G1 studyableType, boolean z, Integer num, String str, UUID uuid, String str2, Boolean bool) {
        Companion companion = b;
        companion.getClass();
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        Intrinsics.checkNotNullParameter(modeType, "modeType");
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        return Companion.b(companion, action, studySessionId, modeType, l, l2, l3, j, studyableType, z, num, str, uuid, str2, null, bool, 524288);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!StudyEventLog.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type com.quizlet.eventlogger.model.StudyEventLog");
        StudyEventLog studyEventLog = (StudyEventLog) obj;
        return Intrinsics.b(getPayload(), studyEventLog.getPayload()) && Intrinsics.b(getStudySessionId(), studyEventLog.getStudySessionId()) && Intrinsics.b(getStudyModeScreen(), studyEventLog.getStudyModeScreen());
    }

    @JsonIgnore
    public final String getStudyModeScreen() {
        return getPayload().getStudyModeScreen();
    }

    @JsonIgnore
    public final String getStudySessionId() {
        return getPayload().getStudySessionId();
    }

    public void setPayload(@NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "<set-?>");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
