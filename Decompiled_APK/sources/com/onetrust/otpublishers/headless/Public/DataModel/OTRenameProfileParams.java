package com.onetrust.otpublishers.headless.Public.DataModel;

import android.support.v4.media.session.a;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class OTRenameProfileParams {
    public final String a;
    public final String b;
    public final String c;

    public static class OTRenameProfileParamsBuilder {
        public String a;
        public String b;
        public String c;

        @NonNull
        public static OTRenameProfileParamsBuilder newInstance() {
            return new OTRenameProfileParamsBuilder();
        }

        @NonNull
        public OTRenameProfileParams build() {
            return new OTRenameProfileParams(this);
        }

        public OTRenameProfileParamsBuilder setIdentifierType(@NonNull String str) {
            this.c = str;
            return this;
        }

        public OTRenameProfileParamsBuilder setNewProfileID(@NonNull String str) {
            this.b = str;
            return this;
        }

        public OTRenameProfileParamsBuilder setOldProfileID(@NonNull String str) {
            this.a = str;
            return this;
        }
    }

    public OTRenameProfileParams(@NonNull OTRenameProfileParamsBuilder oTRenameProfileParamsBuilder) {
        this.a = oTRenameProfileParamsBuilder.a;
        this.b = oTRenameProfileParamsBuilder.b;
        this.c = oTRenameProfileParamsBuilder.c;
    }

    public String getIdentifierType() {
        return this.c;
    }

    public String getNewProfileID() {
        return this.b;
    }

    public String getOldProfileID() {
        return this.a;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("OTProfileSyncParams{oldProfileID=");
        sb.append(this.a);
        sb.append(", newProfileID='");
        sb.append(this.b);
        sb.append("', identifierType='");
        return a.t(sb, this.c, "'}");
    }
}
