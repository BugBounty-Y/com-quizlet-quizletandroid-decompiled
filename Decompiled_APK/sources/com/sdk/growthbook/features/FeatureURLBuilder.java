package com.sdk.growthbook.features;

import com.sdk.growthbook.utils.FeatureRefreshStrategy;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FeatureURLBuilder {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private static final String EVENTS_PATH = "sub";

    @NotNull
    private static final String FEATURE_PATH = "api/features";

    @NotNull
    private static final String REMOTE_FEATURE_PATH = "api/eval";

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[FeatureRefreshStrategy.values().length];
            try {
                iArr[FeatureRefreshStrategy.STALE_WHILE_REVALIDATE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[FeatureRefreshStrategy.SERVER_SENT_EVENTS.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[FeatureRefreshStrategy.SERVER_SENT_REMOTE_FEATURE_EVAL.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public static /* synthetic */ String buildUrl$default(FeatureURLBuilder featureURLBuilder, String str, String str2, FeatureRefreshStrategy featureRefreshStrategy, int i, Object obj) {
        if ((i & 4) != 0) {
            featureRefreshStrategy = FeatureRefreshStrategy.STALE_WHILE_REVALIDATE;
        }
        return featureURLBuilder.buildUrl(str, str2, featureRefreshStrategy);
    }

    @NotNull
    public final String buildUrl(@NotNull String baseUrl, @NotNull String apiKey, @NotNull FeatureRefreshStrategy featureRefreshStrategy) {
        String str;
        String strK;
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(featureRefreshStrategy, "featureRefreshStrategy");
        int i = WhenMappings.$EnumSwitchMapping$0[featureRefreshStrategy.ordinal()];
        if (i == 1) {
            str = FEATURE_PATH;
        } else if (i == 2) {
            str = EVENTS_PATH;
        } else {
            if (i != 3) {
                throw new NoWhenBranchMatchedException();
            }
            str = REMOTE_FEATURE_PATH;
        }
        if (StringsKt.I(baseUrl)) {
            strK = android.support.v4.media.session.a.k(baseUrl, str);
        } else {
            strK = baseUrl + '/' + str;
        }
        return strK + '/' + apiKey;
    }
}
