package com.onetrust.otpublishers.headless.Public.DataModel;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;

/* loaded from: classes2.dex */
public class OTSdkParams {
    public final String a;
    public final String b;
    public final String c;
    public final OTProfileSyncParams d;
    public final OTUXParams e;
    public final String f;
    public final String g;
    public final boolean h;

    public static class SdkParamsBuilder {
        public String a;
        public String b;
        public String c;
        public OTProfileSyncParams d;
        public String e;
        public String f;
        public OTUXParams g;
        public boolean h;

        @NonNull
        public static SdkParamsBuilder newInstance() {
            return new SdkParamsBuilder();
        }

        @NonNull
        public OTSdkParams build() {
            return new OTSdkParams(this);
        }

        @NonNull
        public SdkParamsBuilder setAPIVersion(@NonNull String str) {
            this.c = str;
            return this;
        }

        @NonNull
        public SdkParamsBuilder setOTCountryCode(@NonNull String str) {
            this.a = str;
            return this;
        }

        @NonNull
        public SdkParamsBuilder setOTRegionCode(@NonNull String str) {
            this.b = str;
            return this;
        }

        @NonNull
        public SdkParamsBuilder setOTUXParams(@NonNull OTUXParams oTUXParams) {
            this.g = oTUXParams;
            return this;
        }

        @NonNull
        @Deprecated
        public SdkParamsBuilder setOtBannerHeightRatio(@NonNull String str) {
            OTLogger.c("OneTrust", 5, "setOtBannerHeightRatio() method is deprecated and eventually will get removed from SDK. Please configure the banner height from OT admin UI template settings");
            this.f = str;
            return this;
        }

        @NonNull
        public SdkParamsBuilder setProfileSyncParams(@NonNull OTProfileSyncParams oTProfileSyncParams) {
            this.d = oTProfileSyncParams;
            return this;
        }

        @NonNull
        public SdkParamsBuilder setSyncWebSDKConsent(boolean z) {
            this.h = z;
            return this;
        }

        @NonNull
        public SdkParamsBuilder shouldCreateProfile(@NonNull String str) {
            this.e = str;
            return this;
        }
    }

    public OTSdkParams(@NonNull SdkParamsBuilder sdkParamsBuilder) {
        this.a = sdkParamsBuilder.a;
        this.b = sdkParamsBuilder.b;
        this.c = sdkParamsBuilder.c;
        this.d = sdkParamsBuilder.d;
        this.f = sdkParamsBuilder.e;
        this.g = sdkParamsBuilder.f;
        this.e = sdkParamsBuilder.g;
        this.h = sdkParamsBuilder.h;
    }

    public String getCreateProfile() {
        return this.f;
    }

    public String getOTCountryCode() {
        return this.a;
    }

    public String getOTRegionCode() {
        return this.b;
    }

    public String getOTSdkAPIVersion() {
        return this.c;
    }

    public OTUXParams getOTUXParams() {
        return this.e;
    }

    public String getOtBannerHeight() {
        return this.g;
    }

    public OTProfileSyncParams getOtProfileSyncParams() {
        return this.d;
    }

    public boolean getSyncWebSDKConsent() {
        return this.h;
    }
}
