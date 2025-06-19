package com.quizlet.eventlogger.model;

import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.fasterxml.jackson.annotation.JsonProperty;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SearchBannerEventLog extends StandardizedEventLog {
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

        @JsonProperty("banner_name")
        private String bannerName;

        @JsonProperty("banner_type")
        private String bannerType;

        @JsonProperty("banner_url")
        private String bannerUrl;

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
            return Intrinsics.b(this.bannerType, payload.bannerType) && Intrinsics.b(this.bannerName, payload.bannerName) && Intrinsics.b(this.bannerUrl, payload.bannerUrl);
        }

        public final String getBannerName() {
            return this.bannerName;
        }

        public final String getBannerType() {
            return this.bannerType;
        }

        public final String getBannerUrl() {
            return this.bannerUrl;
        }

        public final int hashCode() {
            String str = this.bannerType;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.bannerName;
            int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
            String str3 = this.bannerUrl;
            return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
        }

        public final void setBannerName(String str) {
            this.bannerName = str;
        }

        public final void setBannerType(String str) {
            this.bannerType = str;
        }

        public final void setBannerUrl(String str) {
            this.bannerUrl = str;
        }

        public final String toString() {
            String str = this.bannerType;
            String str2 = this.bannerName;
            return a.t(AbstractC0147y.h("Payload(bannerType=", str, ", bannerName=", str2, ", bannerUrl="), this.bannerUrl, ")");
        }

        public /* synthetic */ Payload(String str, String str2, String str3, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2, (i & 4) != 0 ? null : str3);
        }

        public Payload(String str, String str2, String str3) {
            this.bannerType = str;
            this.bannerName = str2;
            this.bannerUrl = str3;
        }
    }

    public SearchBannerEventLog(@JsonProperty("payload") @NotNull Payload payload) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.payload = payload;
    }

    @Override // com.quizlet.eventlogger.model.StandardizedEventLog
    @NotNull
    public Payload getPayload() {
        return this.payload;
    }
}
