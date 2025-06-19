package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class ProfileNavigationEventLog extends StandardizedEventLog {
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
        private String clickName;

        @JsonProperty("location")
        private String location;

        @JsonProperty("screen_name")
        private String screenName;

        public Payload() {
            this(null, null, null, 7, null);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Payload)) {
                return false;
            }
            Payload payload = (Payload) obj;
            return Intrinsics.b(this.screenName, payload.screenName) && Intrinsics.b(this.clickName, payload.clickName) && Intrinsics.b(this.location, payload.location);
        }

        public final String getClickName() {
            return this.clickName;
        }

        public final String getLocation() {
            return this.location;
        }

        public final String getScreenName() {
            return this.screenName;
        }

        public final int hashCode() {
            String str = this.screenName;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.clickName;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.location;
            return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
        }

        public final void setClickName(String str) {
            this.clickName = str;
        }

        public final void setLocation(String str) {
            this.location = str;
        }

        public final void setScreenName(String str) {
            this.screenName = str;
        }

        public final String toString() {
            String str = this.screenName;
            String str2 = this.clickName;
            return a.t(AbstractC0147y.h("Payload(screenName=", str, ", clickName=", str2, ", location="), this.location, ")");
        }

        public /* synthetic */ Payload(String str, String str2, String str3, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3);
        }

        public Payload(String str, String str2, String str3) {
            this.screenName = str;
            this.clickName = str2;
            this.location = str3;
        }
    }

    public ProfileNavigationEventLog(@JsonProperty("payload") @NotNull Payload payload) {
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
