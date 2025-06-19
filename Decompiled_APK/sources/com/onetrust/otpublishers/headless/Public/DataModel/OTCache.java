package com.onetrust.otpublishers.headless.Public.DataModel;

import android.support.v4.media.session.a;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class OTCache {
    public final String a;

    public static class OTCacheBuilder {
        public String a;

        @NonNull
        public static OTCacheBuilder newInstance() {
            return new OTCacheBuilder();
        }

        @NonNull
        public OTCache build() {
            return new OTCache(this);
        }

        @NonNull
        @Deprecated
        public OTCacheBuilder setDataSubjectIdentifier(@NonNull String str) {
            this.a = str;
            return this;
        }
    }

    public OTCache(@NonNull OTCacheBuilder oTCacheBuilder) {
        this.a = oTCacheBuilder.a;
    }

    public String getDataSubjectIdentifier() {
        return this.a;
    }

    @NonNull
    public String toString() {
        return a.t(new StringBuilder("OTCache{dataSubjectIdentifier='"), this.a, "'}");
    }
}
