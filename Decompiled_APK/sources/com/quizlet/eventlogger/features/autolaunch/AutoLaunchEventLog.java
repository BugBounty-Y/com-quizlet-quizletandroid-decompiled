package com.quizlet.eventlogger.features.autolaunch;

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
public final class AutoLaunchEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static AutoLaunchEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter("flash_card_summary_next_step_type_learn", "id");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload("flash_card_summary_next_step_type_learn", null, null, null, null, null, 62, null);
            payloadModifier.invoke(payload);
            AutoLaunchEventLog autoLaunchEventLog = new AutoLaunchEventLog(payload);
            autoLaunchEventLog.setTable(EnumC4503n.ANDROID_EVENTS);
            autoLaunchEventLog.setAction(action);
            return autoLaunchEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("enableAutoLaunch")
        private Boolean enableAutoLaunch;

        @JsonProperty("id")
        @NotNull
        private String id;

        @JsonProperty("reason")
        private String reason;

        @JsonProperty("secondsPassed")
        private Integer secondsPassed;

        @JsonProperty("waitSeconds")
        private Long waitSeconds;

        @JsonProperty("withinWaitSeconds")
        private Boolean withinWaitSeconds;

        public /* synthetic */ Payload(String str, Long l, Boolean bool, Boolean bool2, String str2, Integer num, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this(str, (i & 2) != 0 ? null : l, (i & 4) != 0 ? null : bool, (i & 8) != 0 ? null : bool2, (i & 16) != 0 ? null : str2, (i & 32) != 0 ? null : num);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.id, payload.id) && Intrinsics.b(this.waitSeconds, payload.waitSeconds) && Intrinsics.b(this.enableAutoLaunch, payload.enableAutoLaunch) && Intrinsics.b(this.withinWaitSeconds, payload.withinWaitSeconds) && Intrinsics.b(this.reason, payload.reason) && Intrinsics.b(this.secondsPassed, payload.secondsPassed);
        }

        public final Boolean getEnableAutoLaunch() {
            return this.enableAutoLaunch;
        }

        @NotNull
        public final String getId() {
            return this.id;
        }

        public final String getReason() {
            return this.reason;
        }

        public final Integer getSecondsPassed() {
            return this.secondsPassed;
        }

        public final Long getWaitSeconds() {
            return this.waitSeconds;
        }

        public final Boolean getWithinWaitSeconds() {
            return this.withinWaitSeconds;
        }

        public final int hashCode() {
            int iHashCode = this.id.hashCode() * 31;
            Long l = this.waitSeconds;
            int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
            Boolean bool = this.enableAutoLaunch;
            int iHashCode3 = (iHashCode2 + (bool == null ? 0 : bool.hashCode())) * 31;
            Boolean bool2 = this.withinWaitSeconds;
            int iHashCode4 = (iHashCode3 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
            String str = this.reason;
            int iHashCode5 = (iHashCode4 + (str == null ? 0 : str.hashCode())) * 31;
            Integer num = this.secondsPassed;
            return iHashCode5 + (num != null ? num.hashCode() : 0);
        }

        public final void setEnableAutoLaunch(Boolean bool) {
            this.enableAutoLaunch = bool;
        }

        public final void setId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.id = str;
        }

        public final void setReason(String str) {
            this.reason = str;
        }

        public final void setSecondsPassed(Integer num) {
            this.secondsPassed = num;
        }

        public final void setWaitSeconds(Long l) {
            this.waitSeconds = l;
        }

        public final void setWithinWaitSeconds(Boolean bool) {
            this.withinWaitSeconds = bool;
        }

        public final String toString() {
            return "Payload(id=" + this.id + ", waitSeconds=" + this.waitSeconds + ", enableAutoLaunch=" + this.enableAutoLaunch + ", withinWaitSeconds=" + this.withinWaitSeconds + ", reason=" + this.reason + ", secondsPassed=" + this.secondsPassed + ")";
        }

        public Payload(@NotNull String id, Long l, Boolean bool, Boolean bool2, String str, Integer num) {
            Intrinsics.checkNotNullParameter(id, "id");
            this.id = id;
            this.waitSeconds = l;
            this.enableAutoLaunch = bool;
            this.withinWaitSeconds = bool2;
            this.reason = str;
            this.secondsPassed = num;
        }
    }

    public AutoLaunchEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
