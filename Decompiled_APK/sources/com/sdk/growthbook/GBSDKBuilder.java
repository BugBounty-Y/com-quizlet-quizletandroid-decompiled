package com.sdk.growthbook;

import com.sdk.growthbook.model.GBContext;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeatureResult;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.network.NetworkDispatcher;
import com.sdk.growthbook.sandbox.CachingImpl;
import com.sdk.growthbook.stickybucket.GBStickyBucketService;
import com.sdk.growthbook.stickybucket.GBStickyBucketServiceImp;
import com.sdk.growthbook.utils.GBError;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBSDKBuilder extends SDKBuilder {
    private Function2<? super String, ? super GBFeatureResult, Unit> featureUsageCallback;
    private Function2<? super Boolean, ? super GBError, Unit> refreshHandler;
    private GBStickyBucketService stickyBucketService;

    /*  JADX ERROR: NullPointerException in pass: InitCodeVariables
        java.lang.NullPointerException
        */
    public /* synthetic */ GBSDKBuilder(java.lang.String r12, java.lang.String r13, com.sdk.growthbook.network.NetworkDispatcher r14, java.util.Map r15, java.lang.String r16, kotlin.jvm.functions.Function2 r17, boolean r18, boolean r19, int r20, kotlin.jvm.internal.DefaultConstructorMarker r21) {
        /*
            r11 = this;
            r0 = r20
            r1 = r0 & 16
            if (r1 == 0) goto L9
            r1 = 0
            r7 = r1
            goto Lb
        L9:
            r7 = r16
        Lb:
            r1 = r0 & 64
            r2 = 0
            if (r1 == 0) goto L12
            r9 = r2
            goto L14
        L12:
            r9 = r18
        L14:
            r0 = r0 & 128(0x80, float:1.8E-43)
            if (r0 == 0) goto L21
            r10 = r2
            r3 = r12
            r4 = r13
            r5 = r14
            r6 = r15
            r8 = r17
            r2 = r11
            goto L2a
        L21:
            r10 = r19
            r2 = r11
            r3 = r12
            r4 = r13
            r5 = r14
            r6 = r15
            r8 = r17
        L2a:
            r2.<init>(r3, r4, r5, r6, r7, r8, r9, r10)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.GBSDKBuilder.<init>(java.lang.String, java.lang.String, com.sdk.growthbook.network.NetworkDispatcher, java.util.Map, java.lang.String, kotlin.jvm.functions.Function2, boolean, boolean, int, kotlin.jvm.internal.DefaultConstructorMarker):void");
    }

    public static /* synthetic */ GBSDKBuilder setPrefixForStickyBucketCachedDirectory$default(GBSDKBuilder gBSDKBuilder, String str, int i, Object obj) {
        if ((i & 1) != 0) {
            str = "gbStickyBuckets__";
        }
        return gBSDKBuilder.setPrefixForStickyBucketCachedDirectory(str);
    }

    public static /* synthetic */ GBSDKBuilder setStickyBucketService$default(GBSDKBuilder gBSDKBuilder, GBStickyBucketService gBStickyBucketService, int i, Object obj) {
        if ((i & 1) != 0) {
            gBStickyBucketService = new GBStickyBucketServiceImp(null, CachingImpl.INSTANCE.getLayer(), 1, null);
        }
        return gBSDKBuilder.setStickyBucketService(gBStickyBucketService);
    }

    @Override // com.sdk.growthbook.SDKBuilder
    @NotNull
    public GrowthBookSDK initialize() {
        String apiKey = getApiKey();
        boolean enabled$GrowthBook_release = getEnabled$GrowthBook_release();
        Map<String, GBValue> attributes = getAttributes();
        String hostURL = getHostURL();
        boolean qaMode$GrowthBook_release = getQaMode$GrowthBook_release();
        Map<String, Integer> forcedVariations$GrowthBook_release = getForcedVariations$GrowthBook_release();
        Function2<GBExperiment, GBExperimentResult, Unit> trackingCallback = getTrackingCallback();
        Function2<? super String, ? super GBFeatureResult, Unit> function2 = this.featureUsageCallback;
        return new GrowthBookSDK(new GBContext(apiKey, hostURL, enabled$GrowthBook_release, getEncryptionKey(), attributes, forcedVariations$GrowthBook_release, null, null, this.stickyBucketService, qaMode$GrowthBook_release, trackingCallback, function2, getRemoteEval(), getEnableLogging(), null, 16576, null), this.refreshHandler, getNetworkDispatcher(), null, null, 24, null);
    }

    @NotNull
    public final GBSDKBuilder setFeatureUsageCallback(@NotNull Function2<? super String, ? super GBFeatureResult, Unit> featureUsageCallback) {
        Intrinsics.checkNotNullParameter(featureUsageCallback, "featureUsageCallback");
        this.featureUsageCallback = featureUsageCallback;
        return this;
    }

    @NotNull
    public final GBSDKBuilder setPrefixForStickyBucketCachedDirectory(@NotNull String prefix) {
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        this.stickyBucketService = new GBStickyBucketServiceImp(prefix, CachingImpl.INSTANCE.getLayer());
        return this;
    }

    @NotNull
    public final GBSDKBuilder setRefreshHandler(@NotNull Function2<? super Boolean, ? super GBError, Unit> refreshHandler) {
        Intrinsics.checkNotNullParameter(refreshHandler, "refreshHandler");
        this.refreshHandler = refreshHandler;
        return this;
    }

    @NotNull
    public final GBSDKBuilder setStickyBucketService(@NotNull GBStickyBucketService stickyBucketService) {
        Intrinsics.checkNotNullParameter(stickyBucketService, "stickyBucketService");
        this.stickyBucketService = stickyBucketService;
        return this;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public GBSDKBuilder(@NotNull String apiKey, @NotNull String hostURL, @NotNull NetworkDispatcher networkDispatcher, @NotNull Map<String, ? extends GBValue> attributes, String str, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, boolean z, boolean z2) {
        super(apiKey, hostURL, attributes, trackingCallback, str, networkDispatcher, z, z2);
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(hostURL, "hostURL");
        Intrinsics.checkNotNullParameter(networkDispatcher, "networkDispatcher");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
    }
}
