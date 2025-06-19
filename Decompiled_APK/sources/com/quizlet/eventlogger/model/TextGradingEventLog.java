package com.quizlet.eventlogger.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.eventlogger.model.EventLog;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.Date;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class TextGradingEventLog extends StandardizedEventLog {

    @NotNull
    private static final String KOTLIN_GRADING_MODEL = "kotlin";
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    private Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    public TextGradingEventLog() {
        setTable(EnumC4503n.TEXT_GRADING_EVENTS);
    }

    public void setPayload(Payload payload) {
        this.payload = payload;
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("action")
        @NotNull
        private String action;

        @JsonProperty("client_timestamp")
        @JsonDeserialize(using = EventLog.DateDeserializer.class)
        @JsonSerialize(using = EventLog.DateSerializer.class)
        @NotNull
        private Date clientTimestamp;

        @JsonProperty("cnn_score")
        private Double cnn_score;

        @JsonProperty("displayed_grade")
        private String displayedGrade;

        @JsonProperty("expected_answer_text")
        private String expectedAnswerText;

        @JsonProperty("grade")
        private String grade;

        @JsonProperty("missing_text")
        private String missingText;

        @JsonProperty("model_name")
        private String model;

        @JsonProperty("other")
        private String other;

        @JsonProperty("question_session_id")
        @NotNull
        private String questionSessionId;

        @JsonProperty("request_successful")
        private Boolean requestSuccessful;

        @JsonProperty(DBSessionFields.Names.SCORE)
        private Double score;

        @JsonProperty("study_session_id")
        @NotNull
        private String studySessionId;

        @JsonProperty("submitted_answer_text")
        private String submittedAnswerText;

        /*  JADX ERROR: NullPointerException in pass: InitCodeVariables
            java.lang.NullPointerException
            */
        public /* synthetic */ Payload(java.lang.String r18, java.lang.String r19, java.lang.String r20, java.util.Date r21, java.lang.String r22, java.lang.String r23, java.lang.String r24, java.lang.String r25, java.lang.String r26, java.lang.String r27, java.lang.Double r28, java.lang.Double r29, java.lang.Boolean r30, java.lang.String r31, int r32, kotlin.jvm.internal.DefaultConstructorMarker r33) {
            /*
                r17 = this;
                r0 = r32
                r1 = r0 & 8
                if (r1 == 0) goto Ld
                java.util.Date r1 = new java.util.Date
                r1.<init>()
                r6 = r1
                goto Lf
            Ld:
                r6 = r21
            Lf:
                r1 = r0 & 16
                r2 = 0
                if (r1 == 0) goto L16
                r7 = r2
                goto L18
            L16:
                r7 = r22
            L18:
                r1 = r0 & 32
                if (r1 == 0) goto L1e
                r8 = r2
                goto L20
            L1e:
                r8 = r23
            L20:
                r1 = r0 & 64
                if (r1 == 0) goto L26
                r9 = r2
                goto L28
            L26:
                r9 = r24
            L28:
                r1 = r0 & 128(0x80, float:1.8E-43)
                if (r1 == 0) goto L2e
                r10 = r2
                goto L30
            L2e:
                r10 = r25
            L30:
                r1 = r0 & 256(0x100, float:3.59E-43)
                if (r1 == 0) goto L36
                r11 = r2
                goto L38
            L36:
                r11 = r26
            L38:
                r1 = r0 & 512(0x200, float:7.17E-43)
                if (r1 == 0) goto L3e
                r12 = r2
                goto L40
            L3e:
                r12 = r27
            L40:
                r1 = r0 & 1024(0x400, float:1.435E-42)
                if (r1 == 0) goto L46
                r13 = r2
                goto L48
            L46:
                r13 = r28
            L48:
                r1 = r0 & 2048(0x800, float:2.87E-42)
                if (r1 == 0) goto L4e
                r14 = r2
                goto L50
            L4e:
                r14 = r29
            L50:
                r1 = r0 & 4096(0x1000, float:5.74E-42)
                if (r1 == 0) goto L56
                r15 = r2
                goto L58
            L56:
                r15 = r30
            L58:
                r0 = r0 & 8192(0x2000, float:1.148E-41)
                if (r0 == 0) goto L67
                r16 = r2
                r3 = r18
                r4 = r19
                r5 = r20
                r2 = r17
                goto L71
            L67:
                r16 = r31
                r2 = r17
                r3 = r18
                r4 = r19
                r5 = r20
            L71:
                r2.<init>(r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16)
                return
            */
            throw new UnsupportedOperationException("Method not decompiled: com.quizlet.eventlogger.model.TextGradingEventLog.Payload.<init>(java.lang.String, java.lang.String, java.lang.String, java.util.Date, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.Double, java.lang.Double, java.lang.Boolean, java.lang.String, int, kotlin.jvm.internal.DefaultConstructorMarker):void");
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.action, payload.action) && Intrinsics.b(this.questionSessionId, payload.questionSessionId) && Intrinsics.b(this.studySessionId, payload.studySessionId) && Intrinsics.b(this.clientTimestamp, payload.clientTimestamp) && Intrinsics.b(this.expectedAnswerText, payload.expectedAnswerText) && Intrinsics.b(this.submittedAnswerText, payload.submittedAnswerText) && Intrinsics.b(this.model, payload.model) && Intrinsics.b(this.displayedGrade, payload.displayedGrade) && Intrinsics.b(this.grade, payload.grade) && Intrinsics.b(this.missingText, payload.missingText) && Intrinsics.b(this.score, payload.score) && Intrinsics.b(this.cnn_score, payload.cnn_score) && Intrinsics.b(this.requestSuccessful, payload.requestSuccessful) && Intrinsics.b(this.other, payload.other);
        }

        @NotNull
        public final String getAction() {
            return this.action;
        }

        @NotNull
        public final Date getClientTimestamp() {
            return this.clientTimestamp;
        }

        public final Double getCnn_score() {
            return this.cnn_score;
        }

        public final String getDisplayedGrade() {
            return this.displayedGrade;
        }

        public final String getExpectedAnswerText() {
            return this.expectedAnswerText;
        }

        public final String getGrade() {
            return this.grade;
        }

        public final String getMissingText() {
            return this.missingText;
        }

        public final String getModel() {
            return this.model;
        }

        public final String getOther() {
            return this.other;
        }

        @NotNull
        public final String getQuestionSessionId() {
            return this.questionSessionId;
        }

        public final Boolean getRequestSuccessful() {
            return this.requestSuccessful;
        }

        public final Double getScore() {
            return this.score;
        }

        @NotNull
        public final String getStudySessionId() {
            return this.studySessionId;
        }

        public final String getSubmittedAnswerText() {
            return this.submittedAnswerText;
        }

        public final int hashCode() {
            int iHashCode = (this.clientTimestamp.hashCode() + d0.e(d0.e(this.action.hashCode() * 31, 31, this.questionSessionId), 31, this.studySessionId)) * 31;
            String str = this.expectedAnswerText;
            int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.submittedAnswerText;
            int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.model;
            int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.displayedGrade;
            int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.grade;
            int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.missingText;
            int iHashCode7 = (iHashCode6 + (str6 == null ? 0 : str6.hashCode())) * 31;
            Double d = this.score;
            int iHashCode8 = (iHashCode7 + (d == null ? 0 : d.hashCode())) * 31;
            Double d2 = this.cnn_score;
            int iHashCode9 = (iHashCode8 + (d2 == null ? 0 : d2.hashCode())) * 31;
            Boolean bool = this.requestSuccessful;
            int iHashCode10 = (iHashCode9 + (bool == null ? 0 : bool.hashCode())) * 31;
            String str7 = this.other;
            return iHashCode10 + (str7 != null ? str7.hashCode() : 0);
        }

        public final void setAction(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.action = str;
        }

        public final void setClientTimestamp(@NotNull Date date) {
            Intrinsics.checkNotNullParameter(date, "<set-?>");
            this.clientTimestamp = date;
        }

        public final void setCnn_score(Double d) {
            this.cnn_score = d;
        }

        public final void setDisplayedGrade(String str) {
            this.displayedGrade = str;
        }

        public final void setExpectedAnswerText(String str) {
            this.expectedAnswerText = str;
        }

        public final void setGrade(String str) {
            this.grade = str;
        }

        public final void setMissingText(String str) {
            this.missingText = str;
        }

        public final void setModel(String str) {
            this.model = str;
        }

        public final void setOther(String str) {
            this.other = str;
        }

        public final void setQuestionSessionId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.questionSessionId = str;
        }

        public final void setRequestSuccessful(Boolean bool) {
            this.requestSuccessful = bool;
        }

        public final void setScore(Double d) {
            this.score = d;
        }

        public final void setStudySessionId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.studySessionId = str;
        }

        public final void setSubmittedAnswerText(String str) {
            this.submittedAnswerText = str;
        }

        public final String toString() {
            String str = this.action;
            String str2 = this.questionSessionId;
            String str3 = this.studySessionId;
            Date date = this.clientTimestamp;
            String str4 = this.expectedAnswerText;
            String str5 = this.submittedAnswerText;
            String str6 = this.model;
            String str7 = this.displayedGrade;
            String str8 = this.grade;
            String str9 = this.missingText;
            Double d = this.score;
            Double d2 = this.cnn_score;
            Boolean bool = this.requestSuccessful;
            String str10 = this.other;
            StringBuilder sbH = AbstractC0147y.h("Payload(action=", str, ", questionSessionId=", str2, ", studySessionId=");
            sbH.append(str3);
            sbH.append(", clientTimestamp=");
            sbH.append(date);
            sbH.append(", expectedAnswerText=");
            B.u(sbH, str4, ", submittedAnswerText=", str5, ", model=");
            B.u(sbH, str6, ", displayedGrade=", str7, ", grade=");
            B.u(sbH, str8, ", missingText=", str9, ", score=");
            sbH.append(d);
            sbH.append(", cnn_score=");
            sbH.append(d2);
            sbH.append(", requestSuccessful=");
            sbH.append(bool);
            sbH.append(", other=");
            sbH.append(str10);
            sbH.append(")");
            return sbH.toString();
        }

        public Payload(@NotNull String action, @NotNull String questionSessionId, @NotNull String studySessionId, @NotNull Date clientTimestamp, String str, String str2, String str3, String str4, String str5, String str6, Double d, Double d2, Boolean bool, String str7) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(clientTimestamp, "clientTimestamp");
            this.action = action;
            this.questionSessionId = questionSessionId;
            this.studySessionId = studySessionId;
            this.clientTimestamp = clientTimestamp;
            this.expectedAnswerText = str;
            this.submittedAnswerText = str2;
            this.model = str3;
            this.displayedGrade = str4;
            this.grade = str5;
            this.missingText = str6;
            this.score = d;
            this.cnn_score = d2;
            this.requestSuccessful = bool;
            this.other = str7;
        }
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    public Payload getPayload() {
        return this.payload;
    }
}
