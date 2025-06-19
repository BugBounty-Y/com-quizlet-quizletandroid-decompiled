package com.quizlet.eventlogger.features.achievements;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AchievementsToastInteractionEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static AchievementsToastInteractionEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
            payloadModifier.invoke(payload);
            AchievementsToastInteractionEventLog achievementsToastInteractionEventLog = new AchievementsToastInteractionEventLog(payload);
            achievementsToastInteractionEventLog.setAction(action);
            return achievementsToastInteractionEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("notificationId")
        private String notificationId;

        @JsonProperty("viewTime")
        private Integer viewTime;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
        }

        public final void c(Integer num, String str) {
            this.notificationId = str;
            this.viewTime = num;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.notificationId, payload.notificationId) && Intrinsics.b(this.viewTime, payload.viewTime);
        }

        public final String getNotificationId() {
            return this.notificationId;
        }

        public final Integer getViewTime() {
            return this.viewTime;
        }

        public final int hashCode() {
            String str = this.notificationId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Integer num = this.viewTime;
            return iHashCode + (num != null ? num.hashCode() : 0);
        }

        public final void setNotificationId(String str) {
            this.notificationId = str;
        }

        public final void setViewTime(Integer num) {
            this.viewTime = num;
        }

        public final String toString() {
            return "Payload(notificationId=" + this.notificationId + ", viewTime=" + this.viewTime + ")";
        }

        public /* synthetic */ Payload(String str, Integer num, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : num);
        }

        public Payload(String str, Integer num) {
            this.notificationId = str;
            this.viewTime = num;
        }
    }

    public AchievementsToastInteractionEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
