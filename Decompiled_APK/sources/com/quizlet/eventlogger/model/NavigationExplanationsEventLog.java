package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.appsflyer.AdRevenueScheme;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class NavigationExplanationsEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @JsonProperty("click_name")
        @NotNull
        private final String clickName;

        @JsonProperty("location")
        private final String location;

        @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID)
        private final String modelId;

        @JsonProperty(AdRevenueScheme.PLACEMENT)
        private final String placement;

        @JsonProperty("screen_name")
        @NotNull
        private final String screenName;

        public Payload(@NotNull String screenName, String str, @NotNull String clickName, String str2, String str3) {
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            this.screenName = screenName;
            this.location = str;
            this.clickName = clickName;
            this.placement = str2;
            this.modelId = str3;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.screenName, payload.screenName) && Intrinsics.b(this.location, payload.location) && Intrinsics.b(this.clickName, payload.clickName) && Intrinsics.b(this.placement, payload.placement) && Intrinsics.b(this.modelId, payload.modelId);
        }

        @NotNull
        public final String getClickName() {
            return this.clickName;
        }

        public final String getLocation() {
            return this.location;
        }

        public final String getModelId() {
            return this.modelId;
        }

        public final String getPlacement() {
            return this.placement;
        }

        @NotNull
        public final String getScreenName() {
            return this.screenName;
        }

        public final int hashCode() {
            int iHashCode = this.screenName.hashCode() * 31;
            String str = this.location;
            int iE = d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.clickName);
            String str2 = this.placement;
            int iHashCode2 = (iE + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.modelId;
            return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
        }

        public final String toString() {
            String str = this.screenName;
            String str2 = this.location;
            String str3 = this.clickName;
            String str4 = this.placement;
            String str5 = this.modelId;
            StringBuilder sbH = AbstractC0147y.h("Payload(screenName=", str, ", location=", str2, ", clickName=");
            B.u(sbH, str3, ", placement=", str4, ", modelId=");
            return a.t(sbH, str5, ")");
        }
    }

    public NavigationExplanationsEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.NAVIGATION_EVENTS);
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
