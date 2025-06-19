package com.quizlet.eventlogger.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class LearnPostCompletionEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static LearnPostCompletionEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
            payloadModifier.invoke(payload);
            LearnPostCompletionEventLog learnPostCompletionEventLog = new LearnPostCompletionEventLog(payload);
            learnPostCompletionEventLog.setTable(EnumC4503n.ANDROID_EVENTS);
            learnPostCompletionEventLog.setAction(action);
            return learnPostCompletionEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("clicked_button_name")
        private String clickedButtonName;

        @JsonProperty("progress_state")
        private String progressState;

        /* JADX WARN: Multi-variable type inference failed */
        public Payload() {
            this(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.progressState, payload.progressState) && Intrinsics.b(this.clickedButtonName, payload.clickedButtonName);
        }

        public final String getClickedButtonName() {
            return this.clickedButtonName;
        }

        public final String getProgressState() {
            return this.progressState;
        }

        public final int hashCode() {
            String str = this.progressState;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.clickedButtonName;
            return iHashCode + (str2 != null ? str2.hashCode() : 0);
        }

        public final void setClickedButtonName(String str) {
            this.clickedButtonName = str;
        }

        public final void setProgressState(String str) {
            this.progressState = str;
        }

        public final String toString() {
            return AbstractC0147y.e("Payload(progressState=", this.progressState, ", clickedButtonName=", this.clickedButtonName, ")");
        }

        public /* synthetic */ Payload(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2);
        }

        public Payload(String str, String str2) {
            this.progressState = str;
            this.clickedButtonName = str2;
        }
    }

    public LearnPostCompletionEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
