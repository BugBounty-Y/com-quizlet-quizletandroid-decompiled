package com.quizlet.eventlogger.features.studypath;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class StudyPathPayload extends StandardizedPayloadBase {

    @Metadata
    public static final class GoalIntake extends StudyPathPayload {

        @JsonProperty("goal_date_timestamp")
        private Long goalDateTimestampMs;

        @JsonProperty("goal_intake_answer")
        private String goalIntakeAnswer;

        @JsonProperty("goal_intake_options")
        private String goalIntakeOptions;

        @JsonProperty("goal_intake_question")
        private String goalIntakeQuestion;

        @JsonProperty("question_types")
        private String questionTypes;

        @JsonProperty("client_screen_name")
        private String screenName;

        @JsonProperty("set_id")
        private String setId;

        public GoalIntake() {
            this(null, null, null, null, null, null, null, 127, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof GoalIntake)) {
                return false;
            }
            GoalIntake goalIntake = (GoalIntake) obj;
            return Intrinsics.b(this.goalIntakeQuestion, goalIntake.goalIntakeQuestion) && Intrinsics.b(this.goalIntakeAnswer, goalIntake.goalIntakeAnswer) && Intrinsics.b(this.goalDateTimestampMs, goalIntake.goalDateTimestampMs) && Intrinsics.b(this.setId, goalIntake.setId) && Intrinsics.b(this.screenName, goalIntake.screenName) && Intrinsics.b(this.goalIntakeOptions, goalIntake.goalIntakeOptions) && Intrinsics.b(this.questionTypes, goalIntake.questionTypes);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            String str = this.goalIntakeQuestion;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.goalIntakeAnswer;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Long l = this.goalDateTimestampMs;
            int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
            String str3 = this.setId;
            int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.screenName;
            int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.goalIntakeOptions;
            int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
            String str6 = this.questionTypes;
            return iHashCode6 + (str6 != null ? str6.hashCode() : 0);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public void setSetId(String str) {
            this.setId = str;
        }

        public final String toString() {
            String str = this.goalIntakeQuestion;
            String str2 = this.goalIntakeAnswer;
            Long l = this.goalDateTimestampMs;
            String str3 = this.setId;
            String str4 = this.screenName;
            String str5 = this.goalIntakeOptions;
            String str6 = this.questionTypes;
            StringBuilder sbH = AbstractC0147y.h("GoalIntake(goalIntakeQuestion=", str, ", goalIntakeAnswer=", str2, ", goalDateTimestampMs=");
            sbH.append(l);
            sbH.append(", setId=");
            sbH.append(str3);
            sbH.append(", screenName=");
            B.u(sbH, str4, ", goalIntakeOptions=", str5, ", questionTypes=");
            return a.t(sbH, str6, ")");
        }

        public /* synthetic */ GoalIntake(String str, String str2, Long l, String str3, String str4, String str5, String str6, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : str3, (i & 16) != 0 ? null : str4, (i & 32) != 0 ? null : str5, (i & 64) != 0 ? null : str6);
        }

        public GoalIntake(String str, String str2, Long l, String str3, String str4, String str5, String str6) {
            super(null);
            this.goalIntakeQuestion = str;
            this.goalIntakeAnswer = str2;
            this.goalDateTimestampMs = l;
            this.setId = str3;
            this.screenName = str4;
            this.goalIntakeOptions = str5;
            this.questionTypes = str6;
        }
    }

    @Metadata
    public static final class ScreenAction extends StudyPathPayload {

        @JsonProperty("client_screen_name")
        private String screenName;

        @JsonProperty("set_id")
        private String setId;

        /* JADX WARN: Multi-variable type inference failed */
        public ScreenAction() {
            this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof ScreenAction)) {
                return false;
            }
            ScreenAction screenAction = (ScreenAction) obj;
            return Intrinsics.b(this.setId, screenAction.setId) && Intrinsics.b(this.screenName, screenAction.screenName);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            String str = this.setId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.screenName;
            return iHashCode + (str2 != null ? str2.hashCode() : 0);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public void setSetId(String str) {
            this.setId = str;
        }

        public final String toString() {
            return AbstractC0147y.e("ScreenAction(setId=", this.setId, ", screenName=", this.screenName, ")");
        }

        public /* synthetic */ ScreenAction(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2);
        }

        public ScreenAction(String str, String str2) {
            super(null);
            this.setId = str;
            this.screenName = str2;
        }
    }

    @Metadata
    public static final class ScreenLoad extends StudyPathPayload {

        @JsonProperty("goal")
        private Integer goal;

        @JsonProperty("knowledgeLevel")
        private Integer knowledgeLevel;

        @JsonProperty("client_screen_name")
        private String screenName;

        @JsonProperty("set_id")
        private String setId;

        public ScreenLoad() {
            this(null, null, null, null, 15, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof ScreenLoad)) {
                return false;
            }
            ScreenLoad screenLoad = (ScreenLoad) obj;
            return Intrinsics.b(this.setId, screenLoad.setId) && Intrinsics.b(this.screenName, screenLoad.screenName) && Intrinsics.b(this.knowledgeLevel, screenLoad.knowledgeLevel) && Intrinsics.b(this.goal, screenLoad.goal);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            String str = this.setId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.screenName;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            Integer num = this.knowledgeLevel;
            int iHashCode3 = (iHashCode2 + (num == null ? 0 : num.hashCode())) * 31;
            Integer num2 = this.goal;
            return iHashCode3 + (num2 != null ? num2.hashCode() : 0);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public void setSetId(String str) {
            this.setId = str;
        }

        public final String toString() {
            String str = this.setId;
            String str2 = this.screenName;
            Integer num = this.knowledgeLevel;
            Integer num2 = this.goal;
            StringBuilder sbH = AbstractC0147y.h("ScreenLoad(setId=", str, ", screenName=", str2, ", knowledgeLevel=");
            sbH.append(num);
            sbH.append(", goal=");
            sbH.append(num2);
            sbH.append(")");
            return sbH.toString();
        }

        public /* synthetic */ ScreenLoad(String str, String str2, Integer num, Integer num2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : num, (i & 8) != 0 ? null : num2);
        }

        public ScreenLoad(String str, String str2, Integer num, Integer num2) {
            super(null);
            this.setId = str;
            this.screenName = str2;
            this.knowledgeLevel = num;
            this.goal = num2;
        }
    }

    @Metadata
    public static final class SkipDismissAction extends StudyPathPayload {

        @JsonProperty("default_goal")
        @NotNull
        private String defaultGoal;

        @JsonProperty("question_types")
        private String questionTypes;

        @JsonProperty("client_screen_name")
        private String screenName;

        @JsonProperty("set_id")
        private String setId;

        public /* synthetic */ SkipDismissAction(String str, String str2, String str3, String str4, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, str4);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SkipDismissAction)) {
                return false;
            }
            SkipDismissAction skipDismissAction = (SkipDismissAction) obj;
            return Intrinsics.b(this.setId, skipDismissAction.setId) && Intrinsics.b(this.screenName, skipDismissAction.screenName) && Intrinsics.b(this.questionTypes, skipDismissAction.questionTypes) && Intrinsics.b(this.defaultGoal, skipDismissAction.defaultGoal);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            String str = this.setId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.screenName;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.questionTypes;
            return this.defaultGoal.hashCode() + ((iHashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public void setSetId(String str) {
            this.setId = str;
        }

        public final String toString() {
            String str = this.setId;
            String str2 = this.screenName;
            return B.j(AbstractC0147y.h("SkipDismissAction(setId=", str, ", screenName=", str2, ", questionTypes="), this.questionTypes, ", defaultGoal=", this.defaultGoal, ")");
        }

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public SkipDismissAction(String str, String str2, String str3, @NotNull String defaultGoal) {
            super(null);
            Intrinsics.checkNotNullParameter(defaultGoal, "defaultGoal");
            this.setId = str;
            this.screenName = str2;
            this.questionTypes = str3;
            this.defaultGoal = defaultGoal;
        }
    }

    @Metadata
    public static final class UnderstandingAvailability extends StudyPathPayload {

        @JsonProperty("did_receive_metadata")
        private boolean didReceiveMetadata;

        @JsonProperty("set_id")
        private String setId;

        public /* synthetic */ UnderstandingAvailability(String str, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, z);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof UnderstandingAvailability)) {
                return false;
            }
            UnderstandingAvailability understandingAvailability = (UnderstandingAvailability) obj;
            return Intrinsics.b(this.setId, understandingAvailability.setId) && this.didReceiveMetadata == understandingAvailability.didReceiveMetadata;
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public String getSetId() {
            return this.setId;
        }

        public final int hashCode() {
            String str = this.setId;
            return Boolean.hashCode(this.didReceiveMetadata) + ((str == null ? 0 : str.hashCode()) * 31);
        }

        @Override // com.quizlet.eventlogger.features.studypath.StudyPathPayload
        public void setSetId(String str) {
            this.setId = str;
        }

        public final String toString() {
            return "UnderstandingAvailability(setId=" + this.setId + ", didReceiveMetadata=" + this.didReceiveMetadata + ")";
        }

        public UnderstandingAvailability(String str, boolean z) {
            super(null);
            this.setId = str;
            this.didReceiveMetadata = z;
        }
    }

    public /* synthetic */ StudyPathPayload(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    public abstract String getSetId();

    public abstract void setSetId(String str);

    private StudyPathPayload() {
    }
}
