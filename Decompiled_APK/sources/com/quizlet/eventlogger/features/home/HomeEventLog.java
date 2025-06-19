package com.quizlet.eventlogger.features.home;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import com.appsflyer.AdRevenueScheme;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.eventlogger.model.StandardizedEventLog;
import com.quizlet.eventlogger.model.StandardizedPayloadBase;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class HomeEventLog extends StandardizedEventLog {
    public static final Companion b = new Companion(null);

    @NotNull
    private final Payload payload;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static HomeEventLog a(String screenName, String location, String clickName, String action, String str, String str2, String str3, String str4) {
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(location, "location");
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            Intrinsics.checkNotNullParameter(action, "action");
            HomeEventLog homeEventLog = new HomeEventLog(new Payload(screenName, location, clickName, str, str2, str3, null, str4));
            homeEventLog.setAction(action);
            return homeEventLog;
        }

        public static /* synthetic */ HomeEventLog b(Companion companion, String str, String str2, String str3, String str4, String str5, int i) {
            if ((i & 16) != 0) {
                str5 = null;
            }
            companion.getClass();
            return a(str, str2, str3, str4, str5, null, null, null);
        }

        private Companion() {
        }
    }

    @Metadata
    public static final class Payload extends StandardizedPayloadBase {

        @NotNull
        private final String clickName;

        @NotNull
        private final String location;
        private final String model1Id;
        private final String model1Type;
        private final String model2Id;
        private final String model2Type;
        private final String placement;

        @NotNull
        private final String screenName;

        public Payload(@JsonProperty("screen_name") @NotNull String screenName, @JsonProperty("location") @NotNull String location, @JsonProperty("click_name") @NotNull String clickName, @JsonProperty(AdRevenueScheme.PLACEMENT) String str, @JsonProperty(DBOfflineEntityFields.Names.MODEL_ID) String str2, @JsonProperty(DBOfflineEntityFields.Names.MODEL_TYPE) String str3, @JsonProperty("model_id_2") String str4, @JsonProperty("model_type_2") String str5) {
            Intrinsics.checkNotNullParameter(screenName, "screenName");
            Intrinsics.checkNotNullParameter(location, "location");
            Intrinsics.checkNotNullParameter(clickName, "clickName");
            this.screenName = screenName;
            this.location = location;
            this.clickName = clickName;
            this.placement = str;
            this.model1Id = str2;
            this.model1Type = str3;
            this.model2Id = str4;
            this.model2Type = str5;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.screenName, payload.screenName) && Intrinsics.b(this.location, payload.location) && Intrinsics.b(this.clickName, payload.clickName) && Intrinsics.b(this.placement, payload.placement) && Intrinsics.b(this.model1Id, payload.model1Id) && Intrinsics.b(this.model1Type, payload.model1Type) && Intrinsics.b(this.model2Id, payload.model2Id) && Intrinsics.b(this.model2Type, payload.model2Type);
        }

        @NotNull
        public final String getClickName() {
            return this.clickName;
        }

        @NotNull
        public final String getLocation() {
            return this.location;
        }

        public final String getModel1Id() {
            return this.model1Id;
        }

        public final String getModel1Type() {
            return this.model1Type;
        }

        public final String getModel2Id() {
            return this.model2Id;
        }

        public final String getModel2Type() {
            return this.model2Type;
        }

        public final String getPlacement() {
            return this.placement;
        }

        @NotNull
        public final String getScreenName() {
            return this.screenName;
        }

        public final int hashCode() {
            int iE = d0.e(d0.e(this.screenName.hashCode() * 31, 31, this.location), 31, this.clickName);
            String str = this.placement;
            int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.model1Id;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.model1Type;
            int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
            String str4 = this.model2Id;
            int iHashCode4 = (iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31;
            String str5 = this.model2Type;
            return iHashCode4 + (str5 != null ? str5.hashCode() : 0);
        }

        public final String toString() {
            String str = this.screenName;
            String str2 = this.location;
            String str3 = this.clickName;
            String str4 = this.placement;
            String str5 = this.model1Id;
            String str6 = this.model1Type;
            String str7 = this.model2Id;
            String str8 = this.model2Type;
            StringBuilder sbH = AbstractC0147y.h("Payload(screenName=", str, ", location=", str2, ", clickName=");
            B.u(sbH, str3, ", placement=", str4, ", model1Id=");
            B.u(sbH, str5, ", model1Type=", str6, ", model2Id=");
            return B.j(sbH, str7, ", model2Type=", str8, ")");
        }
    }

    public HomeEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
        setTable(EnumC4503n.NAVIGATION_EVENTS);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof HomeEventLog) && Intrinsics.b(this.payload, ((HomeEventLog) obj).payload);
    }

    public final int hashCode() {
        return this.payload.hashCode();
    }

    public final String toString() {
        return "HomeEventLog(payload=" + this.payload + ")";
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
