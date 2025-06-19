package com.pubmatic.sdk.openwrap.core.signal;

import android.os.Bundle;
import androidx.annotation.Keep;
import com.pubmatic.sdk.common.POBAdFormat;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class POBSignalConfig {

    @NotNull
    private final POBAdFormat adFormat;
    private final Bundle extras;

    @Keep
    @Metadata
    public static final class Builder {

        @NotNull
        private final POBAdFormat adFormat;
        private Bundle extras;

        public Builder(@NotNull POBAdFormat adFormat) {
            Intrinsics.checkNotNullParameter(adFormat, "adFormat");
            this.adFormat = adFormat;
        }

        @NotNull
        public final POBSignalConfig build() {
            return new POBSignalConfig(this.adFormat, this.extras, null);
        }

        @NotNull
        public final POBAdFormat getAdFormat() {
            return this.adFormat;
        }

        @NotNull
        public final Builder setExtras(@NotNull Bundle extras) {
            Intrinsics.checkNotNullParameter(extras, "extras");
            this.extras = extras;
            return this;
        }
    }

    public /* synthetic */ POBSignalConfig(POBAdFormat pOBAdFormat, Bundle bundle, DefaultConstructorMarker defaultConstructorMarker) {
        this(pOBAdFormat, bundle);
    }

    @NotNull
    public final POBAdFormat getAdFormat() {
        return this.adFormat;
    }

    public final Bundle getExtras() {
        return this.extras;
    }

    private POBSignalConfig(POBAdFormat pOBAdFormat, Bundle bundle) {
        this.adFormat = pOBAdFormat;
        this.extras = bundle;
    }
}
