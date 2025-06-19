package com.onetrust.otpublishers.headless.Public.DataModel;

import android.support.v4.media.session.a;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class OTProfileSyncParams {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;

    public static class OTProfileSyncParamsBuilder {
        public String a;
        public String b;
        public String c;
        public String d;
        public String e;
        public String f;

        @NonNull
        public static OTProfileSyncParamsBuilder newInstance() {
            return new OTProfileSyncParamsBuilder();
        }

        @NonNull
        public OTProfileSyncParams build() {
            return new OTProfileSyncParams(this);
        }

        public OTProfileSyncParamsBuilder setIdentifier(@NonNull String str) {
            this.b = str;
            return this;
        }

        public OTProfileSyncParamsBuilder setIdentifierType(@NonNull String str) {
            this.c = str;
            return this;
        }

        public OTProfileSyncParamsBuilder setSyncGroupId(@NonNull String str) {
            this.f = str;
            return this;
        }

        public OTProfileSyncParamsBuilder setSyncProfile(@NonNull String str) {
            this.a = str;
            return this;
        }

        public OTProfileSyncParamsBuilder setSyncProfileAuth(@NonNull String str) {
            this.d = str;
            return this;
        }

        public OTProfileSyncParamsBuilder setTenantId(@NonNull String str) {
            this.e = str;
            return this;
        }
    }

    public OTProfileSyncParams(@NonNull OTProfileSyncParamsBuilder oTProfileSyncParamsBuilder) {
        this.a = oTProfileSyncParamsBuilder.a;
        this.b = oTProfileSyncParamsBuilder.b;
        this.c = oTProfileSyncParamsBuilder.c;
        this.d = oTProfileSyncParamsBuilder.d;
        this.e = oTProfileSyncParamsBuilder.e;
        this.f = oTProfileSyncParamsBuilder.f;
    }

    public String getIdentifier() {
        return this.b;
    }

    public String getIdentifierType() {
        return this.c;
    }

    public String getSyncGroupId() {
        return this.f;
    }

    public String getSyncProfile() {
        return this.a;
    }

    public String getSyncProfileAuth() {
        return this.d;
    }

    public String getTenantId() {
        return this.e;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("OTProfileSyncParams{syncProfile=");
        sb.append(this.a);
        sb.append(", identifier='");
        sb.append(this.b);
        sb.append("', identifierType='");
        sb.append(this.c);
        sb.append("', syncProfileAuth='");
        sb.append(this.d);
        sb.append("', tenantId='");
        sb.append(this.e);
        sb.append("', syncGroupId='");
        return a.t(sb, this.f, "'}");
    }
}
