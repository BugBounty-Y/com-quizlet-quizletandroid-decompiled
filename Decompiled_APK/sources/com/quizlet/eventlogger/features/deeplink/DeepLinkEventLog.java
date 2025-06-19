package com.quizlet.eventlogger.features.deeplink;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.node.B;
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
public final class DeepLinkEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static DeepLinkEventLog a(String action, Function1 payloadModifier) {
            Intrinsics.checkNotNullParameter(action, "action");
            Intrinsics.checkNotNullParameter(payloadModifier, "payloadModifier");
            Payload payload = new Payload(null, null, null, null, null, null, 63, null);
            payloadModifier.invoke(payload);
            DeepLinkEventLog deepLinkEventLog = new DeepLinkEventLog(payload);
            deepLinkEventLog.setAction(action);
            return deepLinkEventLog;
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("activity_targets")
        private String activityTargets;

        @JsonProperty("deep_link_error")
        private String deepLinkError;

        @JsonProperty("deep_link_type")
        private String deepLinkType;

        @JsonProperty("is_email_confirmation_redirect")
        private Boolean isEmailConfirmationRedirect;

        @JsonProperty("referrer")
        private String referrer;

        @JsonProperty("uri")
        private String uri;

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
            return Intrinsics.b(this.uri, payload.uri) && Intrinsics.b(this.referrer, payload.referrer) && Intrinsics.b(this.deepLinkType, payload.deepLinkType) && Intrinsics.b(this.activityTargets, payload.activityTargets) && Intrinsics.b(this.isEmailConfirmationRedirect, payload.isEmailConfirmationRedirect) && Intrinsics.b(this.deepLinkError, payload.deepLinkError);
        }

        public final String getActivityTargets() {
            return this.activityTargets;
        }

        public final String getDeepLinkError() {
            return this.deepLinkError;
        }

        public final String getDeepLinkType() {
            return this.deepLinkType;
        }

        public final String getReferrer() {
            return this.referrer;
        }

        public final String getUri() {
            return this.uri;
        }

        public final int hashCode() {
            String str = this.uri;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.referrer;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.deepLinkType;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.activityTargets;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            Boolean bool = this.isEmailConfirmationRedirect;
            int iHashCode5 = (iHashCode4 + (bool == null ? 0 : bool.hashCode())) * 31;
            String str5 = this.deepLinkError;
            return iHashCode5 + (str5 != null ? str5.hashCode() : 0);
        }

        public final void setActivityTargets(String str) {
            this.activityTargets = str;
        }

        public final void setDeepLinkError(String str) {
            this.deepLinkError = str;
        }

        public final void setDeepLinkType(String str) {
            this.deepLinkType = str;
        }

        public final void setEmailConfirmationRedirect(Boolean bool) {
            this.isEmailConfirmationRedirect = bool;
        }

        public final void setReferrer(String str) {
            this.referrer = str;
        }

        public final void setUri(String str) {
            this.uri = str;
        }

        public final String toString() {
            String str = this.uri;
            String str2 = this.referrer;
            String str3 = this.deepLinkType;
            String str4 = this.activityTargets;
            Boolean bool = this.isEmailConfirmationRedirect;
            String str5 = this.deepLinkError;
            StringBuilder sbH = AbstractC0147y.h("Payload(uri=", str, ", referrer=", str2, ", deepLinkType=");
            B.u(sbH, str3, ", activityTargets=", str4, ", isEmailConfirmationRedirect=");
            sbH.append(bool);
            sbH.append(", deepLinkError=");
            sbH.append(str5);
            sbH.append(")");
            return sbH.toString();
        }

        public /* synthetic */ Payload(String str, String str2, String str3, String str4, Boolean bool, String str5, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3, (i & 8) != 0 ? null : str4, (i & 16) != 0 ? null : bool, (i & 32) != 0 ? null : str5);
        }

        public Payload(String str, String str2, String str3, String str4, Boolean bool, String str5) {
            this.uri = str;
            this.referrer = str2;
            this.deepLinkType = str3;
            this.activityTargets = str4;
            this.isEmailConfirmationRedirect = bool;
            this.deepLinkError = str5;
        }
    }

    public DeepLinkEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
