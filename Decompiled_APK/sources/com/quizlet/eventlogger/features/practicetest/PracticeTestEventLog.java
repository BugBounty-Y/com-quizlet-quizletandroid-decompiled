package com.quizlet.eventlogger.features.practicetest;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class PracticeTestEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class AdditionalInfo {

        @JsonProperty("defaultMaxNumberOfQuestions")
        private Integer defaultMaxNumberOfQuestions;

        @JsonProperty("defaultNumberOfQuestions")
        private Integer defaultNumberOfQuestions;

        @JsonProperty("defaultQuestionFormat")
        private String defaultQuestionFormats;

        @JsonProperty("isQuestionListOpened")
        private Boolean isQuestionListOpened;

        @JsonProperty("questionId")
        private String questionId;

        @JsonProperty("questionNumber")
        private Integer questionNumber;

        @JsonProperty("results")
        private String results;

        @JsonProperty(DBSessionFields.Names.SCORE)
        private Integer score;

        @JsonProperty("settings")
        private Settings settings;

        public AdditionalInfo() {
            this(null, null, null, null, null, null, null, null, null, 511, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof AdditionalInfo)) {
                return false;
            }
            AdditionalInfo additionalInfo = (AdditionalInfo) obj;
            return Intrinsics.b(this.settings, additionalInfo.settings) && Intrinsics.b(this.defaultMaxNumberOfQuestions, additionalInfo.defaultMaxNumberOfQuestions) && Intrinsics.b(this.defaultNumberOfQuestions, additionalInfo.defaultNumberOfQuestions) && Intrinsics.b(this.defaultQuestionFormats, additionalInfo.defaultQuestionFormats) && Intrinsics.b(this.questionId, additionalInfo.questionId) && Intrinsics.b(this.questionNumber, additionalInfo.questionNumber) && Intrinsics.b(this.results, additionalInfo.results) && Intrinsics.b(this.score, additionalInfo.score) && Intrinsics.b(this.isQuestionListOpened, additionalInfo.isQuestionListOpened);
        }

        public final Integer getDefaultMaxNumberOfQuestions() {
            return this.defaultMaxNumberOfQuestions;
        }

        public final Integer getDefaultNumberOfQuestions() {
            return this.defaultNumberOfQuestions;
        }

        public final String getDefaultQuestionFormats() {
            return this.defaultQuestionFormats;
        }

        public final String getQuestionId() {
            return this.questionId;
        }

        public final Integer getQuestionNumber() {
            return this.questionNumber;
        }

        public final String getResults() {
            return this.results;
        }

        public final Integer getScore() {
            return this.score;
        }

        public final Settings getSettings() {
            return this.settings;
        }

        public final int hashCode() {
            Settings settings = this.settings;
            int iHashCode = (settings == null ? 0 : settings.hashCode()) * 31;
            Integer num = this.defaultMaxNumberOfQuestions;
            int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
            Integer num2 = this.defaultNumberOfQuestions;
            int iHashCode3 = (iHashCode2 + (num2 == null ? 0 : num2.hashCode())) * 31;
            String str = this.defaultQuestionFormats;
            int iHashCode4 = (iHashCode3 + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.questionId;
            int iHashCode5 = (iHashCode4 + (str2 == null ? 0 : str2.hashCode())) * 31;
            Integer num3 = this.questionNumber;
            int iHashCode6 = (iHashCode5 + (num3 == null ? 0 : num3.hashCode())) * 31;
            String str3 = this.results;
            int iHashCode7 = (iHashCode6 + (str3 == null ? 0 : str3.hashCode())) * 31;
            Integer num4 = this.score;
            int iHashCode8 = (iHashCode7 + (num4 == null ? 0 : num4.hashCode())) * 31;
            Boolean bool = this.isQuestionListOpened;
            return iHashCode8 + (bool != null ? bool.hashCode() : 0);
        }

        public final void setDefaultMaxNumberOfQuestions(Integer num) {
            this.defaultMaxNumberOfQuestions = num;
        }

        public final void setDefaultNumberOfQuestions(Integer num) {
            this.defaultNumberOfQuestions = num;
        }

        public final void setDefaultQuestionFormats(String str) {
            this.defaultQuestionFormats = str;
        }

        public final void setQuestionId(String str) {
            this.questionId = str;
        }

        public final void setQuestionListOpened(Boolean bool) {
            this.isQuestionListOpened = bool;
        }

        public final void setQuestionNumber(Integer num) {
            this.questionNumber = num;
        }

        public final void setResults(String str) {
            this.results = str;
        }

        public final void setScore(Integer num) {
            this.score = num;
        }

        public final void setSettings(Settings settings) {
            this.settings = settings;
        }

        public final String toString() {
            return "AdditionalInfo(settings=" + this.settings + ", defaultMaxNumberOfQuestions=" + this.defaultMaxNumberOfQuestions + ", defaultNumberOfQuestions=" + this.defaultNumberOfQuestions + ", defaultQuestionFormats=" + this.defaultQuestionFormats + ", questionId=" + this.questionId + ", questionNumber=" + this.questionNumber + ", results=" + this.results + ", score=" + this.score + ", isQuestionListOpened=" + this.isQuestionListOpened + ")";
        }

        public AdditionalInfo(Settings settings, Integer num, Integer num2, String str, String str2, Integer num3, String str3, Integer num4, Boolean bool) {
            this.settings = settings;
            this.defaultMaxNumberOfQuestions = num;
            this.defaultNumberOfQuestions = num2;
            this.defaultQuestionFormats = str;
            this.questionId = str2;
            this.questionNumber = num3;
            this.results = str3;
            this.score = num4;
            this.isQuestionListOpened = bool;
        }

        public /* synthetic */ AdditionalInfo(Settings settings, Integer num, Integer num2, String str, String str2, Integer num3, String str3, Integer num4, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : settings, (i & 2) != 0 ? null : num, (i & 4) != 0 ? null : num2, (i & 8) != 0 ? null : str, (i & 16) != 0 ? null : str2, (i & 32) != 0 ? null : num3, (i & 64) != 0 ? null : str3, (i & 128) != 0 ? null : num4, (i & 256) != 0 ? null : bool);
        }
    }

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static PracticeTestEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, null, null, null, null, null, 63, null);
            payloadModifier.invoke(payload);
            payload.setActionName(action);
            PracticeTestEventLog practiceTestEventLog = new PracticeTestEventLog(payload);
            practiceTestEventLog.setTable(EnumC4503n.PRACTICE_TEST_EVENTS);
            practiceTestEventLog.setAction(action);
            return practiceTestEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("action_name")
        private String actionName;

        @JsonProperty("additional_info")
        private AdditionalInfo additionalInfo;

        @JsonProperty("practice_test_instance_id")
        private String practiceTestInstanceId;

        @JsonProperty("practice_test_session_id")
        private String practiceTestSessionId;

        @JsonProperty("question_bank_id")
        private String questionBankId;

        @JsonProperty("screen")
        private String screen;

        public Payload() {
            this(null, null, null, null, null, null, 63, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.practiceTestSessionId, payload.practiceTestSessionId) && Intrinsics.b(this.practiceTestInstanceId, payload.practiceTestInstanceId) && Intrinsics.b(this.questionBankId, payload.questionBankId) && Intrinsics.b(this.screen, payload.screen) && Intrinsics.b(this.actionName, payload.actionName) && Intrinsics.b(this.additionalInfo, payload.additionalInfo);
        }

        public final String getActionName() {
            return this.actionName;
        }

        public final AdditionalInfo getAdditionalInfo() {
            return this.additionalInfo;
        }

        public final String getPracticeTestInstanceId() {
            return this.practiceTestInstanceId;
        }

        public final String getPracticeTestSessionId() {
            return this.practiceTestSessionId;
        }

        public final String getQuestionBankId() {
            return this.questionBankId;
        }

        public final String getScreen() {
            return this.screen;
        }

        public final int hashCode() {
            String str = this.practiceTestSessionId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.practiceTestInstanceId;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.questionBankId;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.screen;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.actionName;
            int iHashCode5 = (iHashCode4 + (str5 == null ? 0 : str5.hashCode())) * 31;
            AdditionalInfo additionalInfo = this.additionalInfo;
            return iHashCode5 + (additionalInfo != null ? additionalInfo.hashCode() : 0);
        }

        public final void setActionName(String str) {
            this.actionName = str;
        }

        public final void setAdditionalInfo(AdditionalInfo additionalInfo) {
            this.additionalInfo = additionalInfo;
        }

        public final void setPracticeTestInstanceId(String str) {
            this.practiceTestInstanceId = str;
        }

        public final void setPracticeTestSessionId(String str) {
            this.practiceTestSessionId = str;
        }

        public final void setQuestionBankId(String str) {
            this.questionBankId = str;
        }

        public final void setScreen(String str) {
            this.screen = str;
        }

        public final String toString() {
            String str = this.practiceTestSessionId;
            String str2 = this.practiceTestInstanceId;
            String str3 = this.questionBankId;
            String str4 = this.screen;
            String str5 = this.actionName;
            AdditionalInfo additionalInfo = this.additionalInfo;
            StringBuilder sbH = AbstractC0147y.h("Payload(practiceTestSessionId=", str, ", practiceTestInstanceId=", str2, ", questionBankId=");
            B.u(sbH, str3, ", screen=", str4, ", actionName=");
            sbH.append(str5);
            sbH.append(", additionalInfo=");
            sbH.append(additionalInfo);
            sbH.append(")");
            return sbH.toString();
        }

        public /* synthetic */ Payload(String str, String str2, String str3, String str4, String str5, AdditionalInfo additionalInfo, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : str4, (i & 16) != 0 ? null : str5, (i & 32) != 0 ? null : additionalInfo);
        }

        public Payload(String str, String str2, String str3, String str4, String str5, AdditionalInfo additionalInfo) {
            this.practiceTestSessionId = str;
            this.practiceTestInstanceId = str2;
            this.questionBankId = str3;
            this.screen = str4;
            this.actionName = str5;
            this.additionalInfo = additionalInfo;
        }
    }

    @Metadata
    public static final class Settings {

        @JsonProperty("questionCount")
        private final int questionCount;

        @JsonProperty("questionFormats")
        @NotNull
        private final List<String> questionFormats;

        public Settings(int i, @NotNull List<String> questionFormats) {
            Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
            this.questionCount = i;
            this.questionFormats = questionFormats;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Settings)) {
                return false;
            }
            Settings settings = (Settings) obj;
            return this.questionCount == settings.questionCount && Intrinsics.b(this.questionFormats, settings.questionFormats);
        }

        public final int getQuestionCount() {
            return this.questionCount;
        }

        @NotNull
        public final List<String> getQuestionFormats() {
            return this.questionFormats;
        }

        public final int hashCode() {
            return this.questionFormats.hashCode() + (Integer.hashCode(this.questionCount) * 31);
        }

        public final String toString() {
            return "Settings(questionCount=" + this.questionCount + ", questionFormats=" + this.questionFormats + ")";
        }
    }

    public PracticeTestEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
