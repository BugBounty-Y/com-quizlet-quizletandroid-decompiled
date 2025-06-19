package com.google.android.gms.ads.admanager;

import android.os.Bundle;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.g;

/* loaded from: classes2.dex */
public final class AdManagerAdRequest extends g {

    public static final class Builder extends com.google.android.gms.ads.a {
        @NonNull
        public Builder addCategoryExclusion(@NonNull String str) {
            this.zza.f.add(str);
            return this;
        }

        @NonNull
        public AdManagerAdRequest build() {
            return new AdManagerAdRequest(this, null);
        }

        @Override // com.google.android.gms.ads.a
        @NonNull
        public final /* bridge */ /* synthetic */ com.google.android.gms.ads.a self() {
            return this;
        }

        @NonNull
        public Builder setPublisherProvidedId(@NonNull String str) {
            this.zza.i = str;
            return this;
        }

        @Override // com.google.android.gms.ads.a
        @NonNull
        public Builder self() {
            return this;
        }
    }

    public /* synthetic */ AdManagerAdRequest(Builder builder, b bVar) {
        super(builder);
    }

    @NonNull
    public Bundle getCustomTargeting() {
        return this.zza.i;
    }

    @NonNull
    public String getPublisherProvidedId() {
        return this.zza.e;
    }
}
