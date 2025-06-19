package com.quizlet.eventlogger.features.learn;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.L;
import com.quizlet.studiablemodels.RoundResultItem;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LearnEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);
    private LearnPayload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static LearnEventLog a(Companion companion, LearnEventAction clickAction, Long l, Long l2, int i) {
            LearnPayload learnPayload = null;
            Object[] objArr = 0;
            if ((i & 2) != 0) {
                l = null;
            }
            if ((i & 4) != 0) {
                l2 = null;
            }
            companion.getClass();
            Intrinsics.checkNotNullParameter(clickAction, "clickAction");
            LearnEventLog learnEventLog = new LearnEventLog(learnPayload, 1, objArr == true ? 1 : 0);
            learnEventLog.setAction(clickAction.getValue());
            learnEventLog.setPayload(new LearnPayload.Click(l, l2, null, null));
            return learnEventLog;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static LearnEventLog b(LearnEventAction modalAction, String studySessionId) {
            Intrinsics.checkNotNullParameter(modalAction, "modalAction");
            Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
            LearnEventLog learnEventLog = new LearnEventLog(null, 1, 0 == true ? 1 : 0);
            learnEventLog.setAction(modalAction.getValue());
            learnEventLog.setPayload(new LearnPayload.FocusedLearnModalPayload(studySessionId));
            return learnEventLog;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static LearnEventLog c(Companion companion, LearnEventAction screenLoadAction, Boolean bool, L l, long j, StudiableTaskProgress studiableTaskProgress, int i) {
            long j2;
            Integer numValueOf;
            Boolean bool2 = Boolean.FALSE;
            LearnPayload learnPayload = null;
            Object[] objArr = 0;
            if ((i & 2) != 0) {
                bool = null;
            }
            if ((i & 4) != 0) {
                bool2 = null;
            }
            StudiableTaskProgress studiableTaskProgress2 = (i & 64) != 0 ? null : studiableTaskProgress;
            companion.getClass();
            Intrinsics.checkNotNullParameter(screenLoadAction, "screenLoadAction");
            LearnEventLog learnEventLog = new LearnEventLog(learnPayload, 1, objArr == true ? 1 : 0);
            learnEventLog.setAction(screenLoadAction.getValue());
            if (l != null) {
                j2 = j;
                numValueOf = Integer.valueOf(l.a());
            } else {
                j2 = j;
                numValueOf = null;
            }
            learnEventLog.setPayload(new LearnPayload.ScreenLoad(bool, bool2, null, numValueOf, j2, studiableTaskProgress2));
            return learnEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static abstract class LearnPayload extends StandardizedPayloadBase {

        @Metadata
        public static final class Click extends LearnPayload {

            @JsonProperty("checkpointView")
            private final Integer checkpointView;

            @JsonProperty("currentTaskProgress")
            private final StudiableTaskProgress currentTaskProgress;

            @JsonProperty("studiableId")
            private final Long studiableId;

            @JsonProperty("termId")
            private final Long termId;

            public Click(Long l, Long l2, StudiableTaskProgress studiableTaskProgress, Integer num) {
                super(null);
                this.studiableId = l;
                this.termId = l2;
                this.currentTaskProgress = studiableTaskProgress;
                this.checkpointView = num;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Click)) {
                    return false;
                }
                Click click = (Click) obj;
                return Intrinsics.b(this.studiableId, click.studiableId) && Intrinsics.b(this.termId, click.termId) && Intrinsics.b(this.currentTaskProgress, click.currentTaskProgress) && Intrinsics.b(this.checkpointView, click.checkpointView);
            }

            public final int hashCode() {
                Long l = this.studiableId;
                int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
                Long l2 = this.termId;
                int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
                StudiableTaskProgress studiableTaskProgress = this.currentTaskProgress;
                int iHashCode3 = (iHashCode2 + (studiableTaskProgress == null ? 0 : studiableTaskProgress.hashCode())) * 31;
                Integer num = this.checkpointView;
                return iHashCode3 + (num != null ? num.hashCode() : 0);
            }

            public final String toString() {
                return "Click(studiableId=" + this.studiableId + ", termId=" + this.termId + ", currentTaskProgress=" + this.currentTaskProgress + ", checkpointView=" + this.checkpointView + ")";
            }
        }

        @Metadata
        public static final class FocusedLearnModalPayload extends LearnPayload {

            @JsonProperty("study_session_id")
            @NotNull
            private final String studySessionId;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public FocusedLearnModalPayload(@NotNull String studySessionId) {
                super(null);
                Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
                this.studySessionId = studySessionId;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof FocusedLearnModalPayload) && Intrinsics.b(this.studySessionId, ((FocusedLearnModalPayload) obj).studySessionId);
            }

            public final int hashCode() {
                return this.studySessionId.hashCode();
            }

            public final String toString() {
                return a.B("FocusedLearnModalPayload(studySessionId=", this.studySessionId, ")");
            }
        }

        @Metadata
        public static final class GoalAndProgressResetSelected extends LearnPayload {

            @JsonProperty("setId")
            private final long setId;

            public GoalAndProgressResetSelected(long j) {
                super(null);
                this.setId = j;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof GoalAndProgressResetSelected) && this.setId == ((GoalAndProgressResetSelected) obj).setId;
            }

            public final int hashCode() {
                return Long.hashCode(this.setId);
            }

            public final String toString() {
                return d0.o(this.setId, "GoalAndProgressResetSelected(setId=", ")");
            }
        }

        @Metadata
        public static final class OnboardingCancelled extends LearnPayload {

            @JsonProperty("studiableId")
            private final long studiableId;

            public OnboardingCancelled(long j) {
                super(null);
                this.studiableId = j;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof OnboardingCancelled) && this.studiableId == ((OnboardingCancelled) obj).studiableId;
            }

            public final int hashCode() {
                return Long.hashCode(this.studiableId);
            }

            public final String toString() {
                return d0.o(this.studiableId, "OnboardingCancelled(studiableId=", ")");
            }
        }

        @Metadata
        public static final class OptionsChange extends LearnPayload {

            @JsonProperty("enabled")
            private final boolean enabled;

            @JsonProperty("studiableId")
            private final Long studiableId;

            public OptionsChange(Long l, boolean z) {
                super(null);
                this.studiableId = l;
                this.enabled = z;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof OptionsChange)) {
                    return false;
                }
                OptionsChange optionsChange = (OptionsChange) obj;
                return Intrinsics.b(this.studiableId, optionsChange.studiableId) && this.enabled == optionsChange.enabled;
            }

            public final int hashCode() {
                Long l = this.studiableId;
                return Boolean.hashCode(this.enabled) + ((l == null ? 0 : l.hashCode()) * 31);
            }

            public final String toString() {
                return "OptionsChange(studiableId=" + this.studiableId + ", enabled=" + this.enabled + ")";
            }
        }

        @Metadata
        public static final class RoundResults extends LearnPayload {

            @JsonProperty("roundResults")
            @NotNull
            private final List<RoundResultItem> roundResults;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public RoundResults(@NotNull List<RoundResultItem> roundResults) {
                super(null);
                Intrinsics.checkNotNullParameter(roundResults, "roundResults");
                this.roundResults = roundResults;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                return (obj instanceof RoundResults) && Intrinsics.b(this.roundResults, ((RoundResults) obj).roundResults);
            }

            public final int hashCode() {
                return this.roundResults.hashCode();
            }

            public final String toString() {
                return "RoundResults(roundResults=" + this.roundResults + ")";
            }
        }

        @Metadata
        public static final class ScreenLoad extends LearnPayload {

            @JsonProperty("checkpointView")
            private final Integer checkpointView;

            @JsonProperty("currentTaskProgress")
            private final StudiableTaskProgress currentTaskProgress;

            @JsonProperty("goal")
            private final Integer goal;

            @JsonProperty("isTaskComplete")
            private final Boolean isTaskComplete;

            @JsonProperty("isTaskSequenceComplete")
            private final Boolean isTaskSequenceComplete;

            @JsonProperty("studiableId")
            private final long studiableId;

            public ScreenLoad(Boolean bool, Boolean bool2, Integer num, Integer num2, long j, StudiableTaskProgress studiableTaskProgress) {
                super(null);
                this.isTaskComplete = bool;
                this.isTaskSequenceComplete = bool2;
                this.goal = num;
                this.checkpointView = num2;
                this.studiableId = j;
                this.currentTaskProgress = studiableTaskProgress;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof ScreenLoad)) {
                    return false;
                }
                ScreenLoad screenLoad = (ScreenLoad) obj;
                return Intrinsics.b(this.isTaskComplete, screenLoad.isTaskComplete) && Intrinsics.b(this.isTaskSequenceComplete, screenLoad.isTaskSequenceComplete) && Intrinsics.b(this.goal, screenLoad.goal) && Intrinsics.b(this.checkpointView, screenLoad.checkpointView) && this.studiableId == screenLoad.studiableId && Intrinsics.b(this.currentTaskProgress, screenLoad.currentTaskProgress);
            }

            public final int hashCode() {
                Boolean bool = this.isTaskComplete;
                int iHashCode = (bool == null ? 0 : bool.hashCode()) * 31;
                Boolean bool2 = this.isTaskSequenceComplete;
                int iHashCode2 = (iHashCode + (bool2 == null ? 0 : bool2.hashCode())) * 31;
                Integer num = this.goal;
                int iHashCode3 = (iHashCode2 + (num == null ? 0 : num.hashCode())) * 31;
                Integer num2 = this.checkpointView;
                int iD = d0.d((iHashCode3 + (num2 == null ? 0 : num2.hashCode())) * 31, 31, this.studiableId);
                StudiableTaskProgress studiableTaskProgress = this.currentTaskProgress;
                return iD + (studiableTaskProgress != null ? studiableTaskProgress.hashCode() : 0);
            }

            public final String toString() {
                return "ScreenLoad(isTaskComplete=" + this.isTaskComplete + ", isTaskSequenceComplete=" + this.isTaskSequenceComplete + ", goal=" + this.goal + ", checkpointView=" + this.checkpointView + ", studiableId=" + this.studiableId + ", currentTaskProgress=" + this.currentTaskProgress + ")";
            }
        }

        @Metadata
        public static final class SettingsScreenCLose extends LearnPayload {

            @JsonProperty("enabledQuestionTypes")
            private final String enabledQuestionTypes;

            @JsonProperty("studiableId")
            private final Long studiableId;

            public SettingsScreenCLose(Long l, String str) {
                super(null);
                this.studiableId = l;
                this.enabledQuestionTypes = str;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof SettingsScreenCLose)) {
                    return false;
                }
                SettingsScreenCLose settingsScreenCLose = (SettingsScreenCLose) obj;
                return Intrinsics.b(this.studiableId, settingsScreenCLose.studiableId) && Intrinsics.b(this.enabledQuestionTypes, settingsScreenCLose.enabledQuestionTypes);
            }

            public final int hashCode() {
                Long l = this.studiableId;
                int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
                String str = this.enabledQuestionTypes;
                return iHashCode + (str != null ? str.hashCode() : 0);
            }

            public final String toString() {
                return "SettingsScreenCLose(studiableId=" + this.studiableId + ", enabledQuestionTypes=" + this.enabledQuestionTypes + ")";
            }
        }

        @Metadata
        public static final class TasksOptOut extends LearnPayload {

            @JsonProperty("isInCthVariant")
            private final boolean isInCthVariant;

            @JsonProperty("studiableId")
            private final Long studiableId;

            public TasksOptOut(Long l, boolean z) {
                super(null);
                this.studiableId = l;
                this.isInCthVariant = z;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof TasksOptOut)) {
                    return false;
                }
                TasksOptOut tasksOptOut = (TasksOptOut) obj;
                return Intrinsics.b(this.studiableId, tasksOptOut.studiableId) && this.isInCthVariant == tasksOptOut.isInCthVariant;
            }

            public final int hashCode() {
                Long l = this.studiableId;
                return Boolean.hashCode(this.isInCthVariant) + ((l == null ? 0 : l.hashCode()) * 31);
            }

            public final String toString() {
                return "TasksOptOut(studiableId=" + this.studiableId + ", isInCthVariant=" + this.isInCthVariant + ")";
            }
        }

        public /* synthetic */ LearnPayload(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private LearnPayload() {
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public LearnEventLog() {
        this(null, 1, 0 == true ? 1 : 0);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LearnEventLog) && Intrinsics.b(this.payload, ((LearnEventLog) obj).payload);
    }

    public final int hashCode() {
        LearnPayload learnPayload = this.payload;
        if (learnPayload == null) {
            return 0;
        }
        return learnPayload.hashCode();
    }

    public void setPayload(LearnPayload learnPayload) {
        this.payload = learnPayload;
    }

    public final String toString() {
        return "LearnEventLog(payload=" + this.payload + ")";
    }

    public /* synthetic */ LearnEventLog(LearnPayload learnPayload, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : learnPayload);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    public LearnPayload getPayload() {
        return this.payload;
    }

    public LearnEventLog(@JsonProperty("payload") LearnPayload learnPayload) {
        this.payload = learnPayload;
    }
}
