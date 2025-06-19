package com.quizlet.eventlogger.features.learnonboarding;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LearnOnboardingEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {

        @Metadata
        public static final class ClientScreenName {
            static {
                new ClientScreenName();
            }

            private ClientScreenName() {
            }
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static LearnOnboardingEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, null, null, null, null, 31, null);
            payloadModifier.invoke(payload);
            LearnOnboardingEventLog learnOnboardingEventLog = new LearnOnboardingEventLog(payload);
            learnOnboardingEventLog.setTable(EnumC4503n.ANDROID_EVENTS);
            learnOnboardingEventLog.setAction(action);
            return learnOnboardingEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("goal")
        private Integer goal;

        @JsonProperty("goal_options")
        private String goalOptions;

        @JsonProperty("knowledge_level")
        private Integer knowledgeLevel;

        @JsonProperty("screen")
        @NotNull
        private final String screen;

        @JsonProperty("set_id")
        private Long setId;

        @JsonProperty("study_mode_type")
        private Integer studyModeType;

        public Payload() {
            this(null, null, null, null, null, 31, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.setId, payload.setId) && Intrinsics.b(this.studyModeType, payload.studyModeType) && Intrinsics.b(this.goalOptions, payload.goalOptions) && Intrinsics.b(this.goal, payload.goal) && Intrinsics.b(this.knowledgeLevel, payload.knowledgeLevel);
        }

        public final Integer getGoal() {
            return this.goal;
        }

        public final String getGoalOptions() {
            return this.goalOptions;
        }

        public final Integer getKnowledgeLevel() {
            return this.knowledgeLevel;
        }

        @NotNull
        public final String getScreen() {
            return this.screen;
        }

        public final Long getSetId() {
            return this.setId;
        }

        public final Integer getStudyModeType() {
            return this.studyModeType;
        }

        public final int hashCode() {
            Long l = this.setId;
            int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
            Integer num = this.studyModeType;
            int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
            String str = this.goalOptions;
            int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
            Integer num2 = this.goal;
            int iHashCode4 = (iHashCode3 + (num2 == null ? 0 : num2.hashCode())) * 31;
            Integer num3 = this.knowledgeLevel;
            return iHashCode4 + (num3 != null ? num3.hashCode() : 0);
        }

        public final void setGoal(Integer num) {
            this.goal = num;
        }

        public final void setGoalOptions(String str) {
            this.goalOptions = str;
        }

        public final void setKnowledgeLevel(Integer num) {
            this.knowledgeLevel = num;
        }

        public final void setSetId(Long l) {
            this.setId = l;
        }

        public final void setStudyModeType(Integer num) {
            this.studyModeType = num;
        }

        public final String toString() {
            Long l = this.setId;
            Integer num = this.studyModeType;
            String str = this.goalOptions;
            Integer num2 = this.goal;
            Integer num3 = this.knowledgeLevel;
            StringBuilder sb = new StringBuilder("Payload(setId=");
            sb.append(l);
            sb.append(", studyModeType=");
            sb.append(num);
            sb.append(", goalOptions=");
            sb.append(str);
            sb.append(", goal=");
            sb.append(num2);
            sb.append(", knowledgeLevel=");
            return assistantMode.refactored.a.l(sb, num3, ")");
        }

        public /* synthetic */ Payload(Long l, Integer num, String str, Integer num2, Integer num3, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : l, (i & 2) != 0 ? null : num, (i & 4) != 0 ? null : str, (i & 8) != 0 ? null : num2, (i & 16) != 0 ? null : num3);
        }

        public Payload(Long l, Integer num, String str, Integer num2, Integer num3) {
            this.setId = l;
            this.studyModeType = num;
            this.goalOptions = str;
            this.goal = num2;
            this.knowledgeLevel = num3;
            this.screen = "goal_intake_simplified";
        }
    }

    public LearnOnboardingEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
