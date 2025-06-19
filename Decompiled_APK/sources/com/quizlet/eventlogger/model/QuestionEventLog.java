package com.quizlet.eventlogger.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import assistantMode.enums.k;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.android.gms.ads.g;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4503n;
import com.quizlet.generated.enums.O1;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @JsonProperty("payload")
    @NotNull
    private Payload payload = new Payload(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1073741823, null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static QuestionEventLog a(String action, String studySessionId, String questionSessionId, Long l, long j, int i, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, O1 o1, O1 promptSide, Integer num, String str, Integer num2, String questionSource, String str2, Long l2, String str3, Boolean bool, A1 a1, k kVar) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            Intrinsics.checkNotNullParameter(questionSessionId, "questionSessionId");
            Intrinsics.checkNotNullParameter(promptSide, "promptSide");
            Intrinsics.checkNotNullParameter(questionSource, "questionSource");
            QuestionEventLog questionEventLog = new QuestionEventLog();
            questionEventLog.setAction(action);
            Integer numValueOf = o1 != null ? Integer.valueOf(o1.a()) : null;
            int iA = promptSide.a();
            questionEventLog.setPayload(new Payload(studySessionId, questionSessionId, l, Long.valueOf(j), Boolean.valueOf(z), Boolean.valueOf(z2), Boolean.valueOf(z3), Boolean.FALSE, Integer.valueOf(i), null, null, Boolean.valueOf(z4), Boolean.valueOf(z5), Boolean.valueOf(z6), numValueOf, Integer.valueOf(iA), num, 0, str, num2, null, null, null, questionSource, str2, l2, str3, bool, a1 != null ? Integer.valueOf(a1.a()) : null, kVar != null ? Integer.valueOf(kVar.a) : null));
            return questionEventLog;
        }

        public static /* synthetic */ QuestionEventLog b(Companion companion, String str, String str2, String str3, Long l, long j, int i, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, O1 o1, O1 o12, Integer num, String str4, String str5, String str6, A1 a1, k kVar, int i2) {
            String str7 = (i2 & 16777216) != 0 ? "" : str5;
            String str8 = (i2 & 134217728) != 0 ? null : str6;
            companion.getClass();
            return a(str, str2, str3, l, j, i, z, z2, z3, z4, z5, z6, o1, o12, num, str4, null, str7, null, null, str8, null, a1, kVar);
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("answer_has_audio")
        private Boolean answerHasAudio;

        @JsonProperty("answer_has_image")
        private Boolean answerHasImage;

        @JsonProperty("answer_has_text")
        private Boolean answerHasText;

        @JsonProperty("answer_option")
        private Integer answerOption;

        @JsonProperty("answer_text")
        private String answerText;

        @JsonProperty("answer_type")
        private Integer answerType;

        @JsonProperty("client_answered_term_id")
        private Long clientAnsweredTermId;

        @JsonProperty("client_prompt_term_id")
        private Long clientPromptTermId;

        @JsonProperty(DBAnswerFields.Names.CORRECTNESS)
        private Integer correctness;

        @JsonProperty("hint_available")
        private Boolean hintAvailable;

        @JsonProperty("hint_has_answer_text")
        private Boolean hintHasAnswerText;

        @JsonProperty("mode_type")
        private Integer modeType;

        @JsonProperty("none_of_above_option_shown")
        private Boolean noneOfAboveOptionShown;

        @JsonProperty("option_count")
        private Integer optionCount;

        @JsonProperty("participation")
        private Integer participation;

        @JsonProperty("prompt_has_answer_audio")
        private Boolean promptHasAnswerAudio;

        @JsonProperty("prompt_has_audio")
        private Boolean promptHasAudio;

        @JsonProperty("prompt_has_image")
        private Boolean promptHasImage;

        @JsonProperty("prompt_has_text")
        private Boolean promptHasText;

        @JsonProperty("prompt_side")
        private Integer promptSide;

        @JsonProperty("question_content")
        private String questionContent;

        @JsonProperty("question_scoring_model_version")
        private String questionScoringModelVersion;

        @JsonProperty("question_session_id")
        private String questionSessionId;

        @JsonProperty("question_source")
        private String questionSource;

        @JsonProperty("question_type")
        private Integer questionType;

        @JsonProperty("reveal_side")
        private Integer revealSide;

        @JsonProperty("scheduled_review_date")
        private Long scheduledReviewDate;

        @JsonProperty("server_answered_term_id")
        private Long serverAnsweredTermId;

        @JsonProperty("server_prompt_term_id")
        private Long serverPromptTermId;

        @JsonProperty("study_session_id")
        private String studySessionId;

        public Payload() {
            this(null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, 1073741823, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.studySessionId, payload.studySessionId) && Intrinsics.b(this.questionSessionId, payload.questionSessionId) && Intrinsics.b(this.serverPromptTermId, payload.serverPromptTermId) && Intrinsics.b(this.clientPromptTermId, payload.clientPromptTermId) && Intrinsics.b(this.promptHasText, payload.promptHasText) && Intrinsics.b(this.promptHasImage, payload.promptHasImage) && Intrinsics.b(this.promptHasAudio, payload.promptHasAudio) && Intrinsics.b(this.promptHasAnswerAudio, payload.promptHasAnswerAudio) && Intrinsics.b(this.answerType, payload.answerType) && Intrinsics.b(this.serverAnsweredTermId, payload.serverAnsweredTermId) && Intrinsics.b(this.clientAnsweredTermId, payload.clientAnsweredTermId) && Intrinsics.b(this.answerHasText, payload.answerHasText) && Intrinsics.b(this.answerHasImage, payload.answerHasImage) && Intrinsics.b(this.answerHasAudio, payload.answerHasAudio) && Intrinsics.b(this.revealSide, payload.revealSide) && Intrinsics.b(this.promptSide, payload.promptSide) && Intrinsics.b(this.correctness, payload.correctness) && Intrinsics.b(this.participation, payload.participation) && Intrinsics.b(this.answerText, payload.answerText) && Intrinsics.b(this.answerOption, payload.answerOption) && Intrinsics.b(this.hintHasAnswerText, payload.hintHasAnswerText) && Intrinsics.b(this.optionCount, payload.optionCount) && Intrinsics.b(this.noneOfAboveOptionShown, payload.noneOfAboveOptionShown) && Intrinsics.b(this.questionSource, payload.questionSource) && Intrinsics.b(this.questionScoringModelVersion, payload.questionScoringModelVersion) && Intrinsics.b(this.scheduledReviewDate, payload.scheduledReviewDate) && Intrinsics.b(this.questionContent, payload.questionContent) && Intrinsics.b(this.hintAvailable, payload.hintAvailable) && Intrinsics.b(this.modeType, payload.modeType) && Intrinsics.b(this.questionType, payload.questionType);
        }

        public final Boolean getAnswerHasAudio() {
            return this.answerHasAudio;
        }

        public final Boolean getAnswerHasImage() {
            return this.answerHasImage;
        }

        public final Boolean getAnswerHasText() {
            return this.answerHasText;
        }

        public final Integer getAnswerOption() {
            return this.answerOption;
        }

        public final String getAnswerText() {
            return this.answerText;
        }

        public final Integer getAnswerType() {
            return this.answerType;
        }

        public final Long getClientAnsweredTermId() {
            return this.clientAnsweredTermId;
        }

        public final Long getClientPromptTermId() {
            return this.clientPromptTermId;
        }

        public final Integer getCorrectness() {
            return this.correctness;
        }

        public final Boolean getHintAvailable() {
            return this.hintAvailable;
        }

        public final Boolean getHintHasAnswerText() {
            return this.hintHasAnswerText;
        }

        public final Integer getModeType() {
            return this.modeType;
        }

        public final Boolean getNoneOfAboveOptionShown() {
            return this.noneOfAboveOptionShown;
        }

        public final Integer getOptionCount() {
            return this.optionCount;
        }

        public final Integer getParticipation() {
            return this.participation;
        }

        public final Boolean getPromptHasAnswerAudio() {
            return this.promptHasAnswerAudio;
        }

        public final Boolean getPromptHasAudio() {
            return this.promptHasAudio;
        }

        public final Boolean getPromptHasImage() {
            return this.promptHasImage;
        }

        public final Boolean getPromptHasText() {
            return this.promptHasText;
        }

        public final Integer getPromptSide() {
            return this.promptSide;
        }

        public final String getQuestionContent() {
            return this.questionContent;
        }

        public final String getQuestionScoringModelVersion() {
            return this.questionScoringModelVersion;
        }

        public final String getQuestionSessionId() {
            return this.questionSessionId;
        }

        public final String getQuestionSource() {
            return this.questionSource;
        }

        public final Integer getQuestionType() {
            return this.questionType;
        }

        public final Integer getRevealSide() {
            return this.revealSide;
        }

        public final Long getScheduledReviewDate() {
            return this.scheduledReviewDate;
        }

        public final Long getServerAnsweredTermId() {
            return this.serverAnsweredTermId;
        }

        public final Long getServerPromptTermId() {
            return this.serverPromptTermId;
        }

        public final String getStudySessionId() {
            return this.studySessionId;
        }

        public final int hashCode() {
            String str = this.studySessionId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.questionSessionId;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Long l = this.serverPromptTermId;
            int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
            Long l2 = this.clientPromptTermId;
            int iHashCode4 = (iHashCode3 + (l2 == null ? 0 : l2.hashCode())) * 31;
            Boolean bool = this.promptHasText;
            int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
            Boolean bool2 = this.promptHasImage;
            int iHashCode6 = (iHashCode5 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
            Boolean bool3 = this.promptHasAudio;
            int iHashCode7 = (iHashCode6 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
            Boolean bool4 = this.promptHasAnswerAudio;
            int iHashCode8 = (iHashCode7 + (bool4 == null ? 0 : bool4.hashCode())) * 31;
            Integer num = this.answerType;
            int iHashCode9 = (iHashCode8 + (num == null ? 0 : num.hashCode())) * 31;
            Long l3 = this.serverAnsweredTermId;
            int iHashCode10 = (iHashCode9 + (l3 == null ? 0 : l3.hashCode())) * 31;
            Long l4 = this.clientAnsweredTermId;
            int iHashCode11 = (iHashCode10 + (l4 == null ? 0 : l4.hashCode())) * 31;
            Boolean bool5 = this.answerHasText;
            int iHashCode12 = (iHashCode11 + (bool5 == null ? 0 : bool5.hashCode())) * 31;
            Boolean bool6 = this.answerHasImage;
            int iHashCode13 = (iHashCode12 + (bool6 == null ? 0 : bool6.hashCode())) * 31;
            Boolean bool7 = this.answerHasAudio;
            int iHashCode14 = (iHashCode13 + (bool7 == null ? 0 : bool7.hashCode())) * 31;
            Integer num2 = this.revealSide;
            int iHashCode15 = (iHashCode14 + (num2 == null ? 0 : num2.hashCode())) * 31;
            Integer num3 = this.promptSide;
            int iHashCode16 = (iHashCode15 + (num3 == null ? 0 : num3.hashCode())) * 31;
            Integer num4 = this.correctness;
            int iHashCode17 = (iHashCode16 + (num4 == null ? 0 : num4.hashCode())) * 31;
            Integer num5 = this.participation;
            int iHashCode18 = (iHashCode17 + (num5 == null ? 0 : num5.hashCode())) * 31;
            String str3 = this.answerText;
            int iHashCode19 = (iHashCode18 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Integer num6 = this.answerOption;
            int iHashCode20 = (iHashCode19 + (num6 == null ? 0 : num6.hashCode())) * 31;
            Boolean bool8 = this.hintHasAnswerText;
            int iHashCode21 = (iHashCode20 + (bool8 == null ? 0 : bool8.hashCode())) * 31;
            Integer num7 = this.optionCount;
            int iHashCode22 = (iHashCode21 + (num7 == null ? 0 : num7.hashCode())) * 31;
            Boolean bool9 = this.noneOfAboveOptionShown;
            int iHashCode23 = (iHashCode22 + (bool9 == null ? 0 : bool9.hashCode())) * 31;
            String str4 = this.questionSource;
            int iHashCode24 = (iHashCode23 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.questionScoringModelVersion;
            int iHashCode25 = (iHashCode24 + (str5 == null ? 0 : str5.hashCode())) * 31;
            Long l5 = this.scheduledReviewDate;
            int iHashCode26 = (iHashCode25 + (l5 == null ? 0 : l5.hashCode())) * 31;
            String str6 = this.questionContent;
            int iHashCode27 = (iHashCode26 + (str6 == null ? 0 : str6.hashCode())) * 31;
            Boolean bool10 = this.hintAvailable;
            int iHashCode28 = (iHashCode27 + (bool10 == null ? 0 : bool10.hashCode())) * 31;
            Integer num8 = this.modeType;
            int iHashCode29 = (iHashCode28 + (num8 == null ? 0 : num8.hashCode())) * 31;
            Integer num9 = this.questionType;
            return iHashCode29 + (num9 != null ? num9.hashCode() : 0);
        }

        public final void setAnswerHasAudio(Boolean bool) {
            this.answerHasAudio = bool;
        }

        public final void setAnswerHasImage(Boolean bool) {
            this.answerHasImage = bool;
        }

        public final void setAnswerHasText(Boolean bool) {
            this.answerHasText = bool;
        }

        public final void setAnswerOption(Integer num) {
            this.answerOption = num;
        }

        public final void setAnswerText(String str) {
            this.answerText = str;
        }

        public final void setAnswerType(Integer num) {
            this.answerType = num;
        }

        public final void setClientAnsweredTermId(Long l) {
            this.clientAnsweredTermId = l;
        }

        public final void setClientPromptTermId(Long l) {
            this.clientPromptTermId = l;
        }

        public final void setCorrectness(Integer num) {
            this.correctness = num;
        }

        public final void setHintAvailable(Boolean bool) {
            this.hintAvailable = bool;
        }

        public final void setHintHasAnswerText(Boolean bool) {
            this.hintHasAnswerText = bool;
        }

        public final void setModeType(Integer num) {
            this.modeType = num;
        }

        public final void setNoneOfAboveOptionShown(Boolean bool) {
            this.noneOfAboveOptionShown = bool;
        }

        public final void setOptionCount(Integer num) {
            this.optionCount = num;
        }

        public final void setParticipation(Integer num) {
            this.participation = num;
        }

        public final void setPromptHasAnswerAudio(Boolean bool) {
            this.promptHasAnswerAudio = bool;
        }

        public final void setPromptHasAudio(Boolean bool) {
            this.promptHasAudio = bool;
        }

        public final void setPromptHasImage(Boolean bool) {
            this.promptHasImage = bool;
        }

        public final void setPromptHasText(Boolean bool) {
            this.promptHasText = bool;
        }

        public final void setPromptSide(Integer num) {
            this.promptSide = num;
        }

        public final void setQuestionContent(String str) {
            this.questionContent = str;
        }

        public final void setQuestionScoringModelVersion(String str) {
            this.questionScoringModelVersion = str;
        }

        public final void setQuestionSessionId(String str) {
            this.questionSessionId = str;
        }

        public final void setQuestionSource(String str) {
            this.questionSource = str;
        }

        public final void setQuestionType(Integer num) {
            this.questionType = num;
        }

        public final void setRevealSide(Integer num) {
            this.revealSide = num;
        }

        public final void setScheduledReviewDate(Long l) {
            this.scheduledReviewDate = l;
        }

        public final void setServerAnsweredTermId(Long l) {
            this.serverAnsweredTermId = l;
        }

        public final void setServerPromptTermId(Long l) {
            this.serverPromptTermId = l;
        }

        public final void setStudySessionId(String str) {
            this.studySessionId = str;
        }

        public final String toString() {
            String str = this.studySessionId;
            String str2 = this.questionSessionId;
            Long l = this.serverPromptTermId;
            Long l2 = this.clientPromptTermId;
            Boolean bool = this.promptHasText;
            Boolean bool2 = this.promptHasImage;
            Boolean bool3 = this.promptHasAudio;
            Boolean bool4 = this.promptHasAnswerAudio;
            Integer num = this.answerType;
            Long l3 = this.serverAnsweredTermId;
            Long l4 = this.clientAnsweredTermId;
            Boolean bool5 = this.answerHasText;
            Boolean bool6 = this.answerHasImage;
            Boolean bool7 = this.answerHasAudio;
            Integer num2 = this.revealSide;
            Integer num3 = this.promptSide;
            Integer num4 = this.correctness;
            Integer num5 = this.participation;
            String str3 = this.answerText;
            Integer num6 = this.answerOption;
            Boolean bool8 = this.hintHasAnswerText;
            Integer num7 = this.optionCount;
            Boolean bool9 = this.noneOfAboveOptionShown;
            String str4 = this.questionSource;
            String str5 = this.questionScoringModelVersion;
            Long l5 = this.scheduledReviewDate;
            String str6 = this.questionContent;
            Boolean bool10 = this.hintAvailable;
            Integer num8 = this.modeType;
            Integer num9 = this.questionType;
            StringBuilder sbH = AbstractC0147y.h("Payload(studySessionId=", str, ", questionSessionId=", str2, ", serverPromptTermId=");
            sbH.append(l);
            sbH.append(", clientPromptTermId=");
            sbH.append(l2);
            sbH.append(", promptHasText=");
            sbH.append(bool);
            sbH.append(", promptHasImage=");
            sbH.append(bool2);
            sbH.append(", promptHasAudio=");
            sbH.append(bool3);
            sbH.append(", promptHasAnswerAudio=");
            sbH.append(bool4);
            sbH.append(", answerType=");
            sbH.append(num);
            sbH.append(", serverAnsweredTermId=");
            sbH.append(l3);
            sbH.append(", clientAnsweredTermId=");
            sbH.append(l4);
            sbH.append(", answerHasText=");
            sbH.append(bool5);
            sbH.append(", answerHasImage=");
            sbH.append(bool6);
            sbH.append(", answerHasAudio=");
            sbH.append(bool7);
            sbH.append(", revealSide=");
            sbH.append(num2);
            sbH.append(", promptSide=");
            sbH.append(num3);
            sbH.append(", correctness=");
            sbH.append(num4);
            sbH.append(", participation=");
            sbH.append(num5);
            sbH.append(", answerText=");
            sbH.append(str3);
            sbH.append(", answerOption=");
            sbH.append(num6);
            sbH.append(", hintHasAnswerText=");
            sbH.append(bool8);
            sbH.append(", optionCount=");
            sbH.append(num7);
            sbH.append(", noneOfAboveOptionShown=");
            sbH.append(bool9);
            sbH.append(", questionSource=");
            sbH.append(str4);
            sbH.append(", questionScoringModelVersion=");
            sbH.append(str5);
            sbH.append(", scheduledReviewDate=");
            sbH.append(l5);
            sbH.append(", questionContent=");
            sbH.append(str6);
            sbH.append(", hintAvailable=");
            sbH.append(bool10);
            sbH.append(", modeType=");
            sbH.append(num8);
            sbH.append(", questionType=");
            sbH.append(num9);
            sbH.append(")");
            return sbH.toString();
        }

        public /* synthetic */ Payload(String str, String str2, Long l, Long l2, Boolean bool, Boolean bool2, Boolean bool3, Boolean bool4, Integer num, Long l3, Long l4, Boolean bool5, Boolean bool6, Boolean bool7, Integer num2, Integer num3, Integer num4, Integer num5, String str3, Integer num6, Boolean bool8, Integer num7, Boolean bool9, String str4, String str5, Long l5, String str6, Boolean bool10, Integer num8, Integer num9, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : l2, (i & 16) != 0 ? null : bool, (i & 32) != 0 ? null : bool2, (i & 64) != 0 ? null : bool3, (i & 128) != 0 ? null : bool4, (i & 256) != 0 ? null : num, (i & g.MAX_CONTENT_URL_LENGTH) != 0 ? null : l3, (i & 1024) != 0 ? null : l4, (i & 2048) != 0 ? null : bool5, (i & 4096) != 0 ? null : bool6, (i & 8192) != 0 ? null : bool7, (i & 16384) != 0 ? null : num2, (i & 32768) != 0 ? null : num3, (i & 65536) != 0 ? null : num4, (i & 131072) != 0 ? null : num5, (i & 262144) != 0 ? null : str3, (i & 524288) != 0 ? null : num6, (i & 1048576) != 0 ? null : bool8, (i & 2097152) != 0 ? null : num7, (i & 4194304) != 0 ? null : bool9, (i & 8388608) != 0 ? null : str4, (i & 16777216) != 0 ? null : str5, (i & 33554432) != 0 ? null : l5, (i & 67108864) != 0 ? null : str6, (i & 134217728) != 0 ? null : bool10, (i & 268435456) != 0 ? null : num8, (i & 536870912) != 0 ? null : num9);
        }

        public Payload(String str, String str2, Long l, Long l2, Boolean bool, Boolean bool2, Boolean bool3, Boolean bool4, Integer num, Long l3, Long l4, Boolean bool5, Boolean bool6, Boolean bool7, Integer num2, Integer num3, Integer num4, Integer num5, String str3, Integer num6, Boolean bool8, Integer num7, Boolean bool9, String str4, String str5, Long l5, String str6, Boolean bool10, Integer num8, Integer num9) {
            this.studySessionId = str;
            this.questionSessionId = str2;
            this.serverPromptTermId = l;
            this.clientPromptTermId = l2;
            this.promptHasText = bool;
            this.promptHasImage = bool2;
            this.promptHasAudio = bool3;
            this.promptHasAnswerAudio = bool4;
            this.answerType = num;
            this.serverAnsweredTermId = l3;
            this.clientAnsweredTermId = l4;
            this.answerHasText = bool5;
            this.answerHasImage = bool6;
            this.answerHasAudio = bool7;
            this.revealSide = num2;
            this.promptSide = num3;
            this.correctness = num4;
            this.participation = num5;
            this.answerText = str3;
            this.answerOption = num6;
            this.hintHasAnswerText = bool8;
            this.optionCount = num7;
            this.noneOfAboveOptionShown = bool9;
            this.questionSource = str4;
            this.questionScoringModelVersion = str5;
            this.scheduledReviewDate = l5;
            this.questionContent = str6;
            this.hintAvailable = bool10;
            this.modeType = num8;
            this.questionType = num9;
        }
    }

    public QuestionEventLog() {
        setTable(EnumC4503n.QUESTION_EVENTS);
    }

    @JsonIgnore
    public final String getAnswerText() {
        return getPayload().getAnswerText();
    }

    @JsonIgnore
    public final String getClientId() {
        return getPayload().getClientId();
    }

    @JsonIgnore
    public final Integer getCorrectness() {
        return getPayload().getCorrectness();
    }

    @JsonIgnore
    public final String getQuestionSessionId() {
        return getPayload().getQuestionSessionId();
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
