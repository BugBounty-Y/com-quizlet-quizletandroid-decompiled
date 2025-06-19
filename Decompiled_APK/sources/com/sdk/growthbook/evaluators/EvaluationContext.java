package com.sdk.growthbook.evaluators;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBFeatureResult;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.stickybucket.GBStickyBucketService;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class EvaluationContext {
    private final boolean enabled;

    @NotNull
    private final GBExperimentHelper experimentHelper;

    @NotNull
    private final Map<String, GBFeature> features;

    @NotNull
    private Map<String, ? extends Object> forcedVariations;
    private final boolean loggingEnabled;
    private final Function2<String, GBFeatureResult, Unit> onFeatureUsage;
    private final Map<String, GBValue> savedGroups;
    private final GBStickyBucketService stickyBucketService;

    @NotNull
    private final Function2<GBExperiment, GBExperimentResult, Unit> trackingCallback;

    @NotNull
    private final UserContext userContext;

    /* JADX WARN: Multi-variable type inference failed */
    public EvaluationContext(boolean z, @NotNull Map<String, GBFeature> features, @NotNull UserContext userContext, boolean z2, Map<String, ? extends GBValue> map, @NotNull Map<String, ? extends Object> forcedVariations, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, GBStickyBucketService gBStickyBucketService, Function2<? super String, ? super GBFeatureResult, Unit> function2) {
        Intrinsics.checkNotNullParameter(features, "features");
        Intrinsics.checkNotNullParameter(userContext, "userContext");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        this.enabled = z;
        this.features = features;
        this.userContext = userContext;
        this.loggingEnabled = z2;
        this.savedGroups = map;
        this.forcedVariations = forcedVariations;
        this.trackingCallback = trackingCallback;
        this.stickyBucketService = gBStickyBucketService;
        this.onFeatureUsage = function2;
        this.experimentHelper = new GBExperimentHelper();
    }

    public static /* synthetic */ EvaluationContext copy$default(EvaluationContext evaluationContext, boolean z, Map map, UserContext userContext, boolean z2, Map map2, Map map3, Function2 function2, GBStickyBucketService gBStickyBucketService, Function2 function22, int i, Object obj) {
        if ((i & 1) != 0) {
            z = evaluationContext.enabled;
        }
        if ((i & 2) != 0) {
            map = evaluationContext.features;
        }
        if ((i & 4) != 0) {
            userContext = evaluationContext.userContext;
        }
        if ((i & 8) != 0) {
            z2 = evaluationContext.loggingEnabled;
        }
        if ((i & 16) != 0) {
            map2 = evaluationContext.savedGroups;
        }
        if ((i & 32) != 0) {
            map3 = evaluationContext.forcedVariations;
        }
        if ((i & 64) != 0) {
            function2 = evaluationContext.trackingCallback;
        }
        if ((i & 128) != 0) {
            gBStickyBucketService = evaluationContext.stickyBucketService;
        }
        if ((i & 256) != 0) {
            function22 = evaluationContext.onFeatureUsage;
        }
        GBStickyBucketService gBStickyBucketService2 = gBStickyBucketService;
        Function2 function23 = function22;
        Map map4 = map3;
        Function2 function24 = function2;
        Map map5 = map2;
        UserContext userContext2 = userContext;
        return evaluationContext.copy(z, map, userContext2, z2, map5, map4, function24, gBStickyBucketService2, function23);
    }

    public final boolean component1() {
        return this.enabled;
    }

    @NotNull
    public final Map<String, GBFeature> component2() {
        return this.features;
    }

    @NotNull
    public final UserContext component3() {
        return this.userContext;
    }

    public final boolean component4() {
        return this.loggingEnabled;
    }

    public final Map<String, GBValue> component5() {
        return this.savedGroups;
    }

    @NotNull
    public final Map<String, Object> component6() {
        return this.forcedVariations;
    }

    @NotNull
    public final Function2<GBExperiment, GBExperimentResult, Unit> component7() {
        return this.trackingCallback;
    }

    public final GBStickyBucketService component8() {
        return this.stickyBucketService;
    }

    public final Function2<String, GBFeatureResult, Unit> component9() {
        return this.onFeatureUsage;
    }

    @NotNull
    public final EvaluationContext copy(boolean z, @NotNull Map<String, GBFeature> features, @NotNull UserContext userContext, boolean z2, Map<String, ? extends GBValue> map, @NotNull Map<String, ? extends Object> forcedVariations, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, GBStickyBucketService gBStickyBucketService, Function2<? super String, ? super GBFeatureResult, Unit> function2) {
        Intrinsics.checkNotNullParameter(features, "features");
        Intrinsics.checkNotNullParameter(userContext, "userContext");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        return new EvaluationContext(z, features, userContext, z2, map, forcedVariations, trackingCallback, gBStickyBucketService, function2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof EvaluationContext)) {
            return false;
        }
        EvaluationContext evaluationContext = (EvaluationContext) obj;
        return this.enabled == evaluationContext.enabled && Intrinsics.b(this.features, evaluationContext.features) && Intrinsics.b(this.userContext, evaluationContext.userContext) && this.loggingEnabled == evaluationContext.loggingEnabled && Intrinsics.b(this.savedGroups, evaluationContext.savedGroups) && Intrinsics.b(this.forcedVariations, evaluationContext.forcedVariations) && Intrinsics.b(this.trackingCallback, evaluationContext.trackingCallback) && Intrinsics.b(this.stickyBucketService, evaluationContext.stickyBucketService) && Intrinsics.b(this.onFeatureUsage, evaluationContext.onFeatureUsage);
    }

    public final boolean getEnabled() {
        return this.enabled;
    }

    @NotNull
    public final GBExperimentHelper getExperimentHelper$GrowthBook_release() {
        return this.experimentHelper;
    }

    @NotNull
    public final Map<String, GBFeature> getFeatures() {
        return this.features;
    }

    @NotNull
    public final Map<String, Object> getForcedVariations() {
        return this.forcedVariations;
    }

    public final boolean getLoggingEnabled() {
        return this.loggingEnabled;
    }

    public final Function2<String, GBFeatureResult, Unit> getOnFeatureUsage() {
        return this.onFeatureUsage;
    }

    public final Map<String, GBValue> getSavedGroups() {
        return this.savedGroups;
    }

    public final GBStickyBucketService getStickyBucketService() {
        return this.stickyBucketService;
    }

    @NotNull
    public final Function2<GBExperiment, GBExperimentResult, Unit> getTrackingCallback() {
        return this.trackingCallback;
    }

    @NotNull
    public final UserContext getUserContext() {
        return this.userContext;
    }

    public int hashCode() {
        int iG = d0.g((this.userContext.hashCode() + a.d(Boolean.hashCode(this.enabled) * 31, 31, this.features)) * 31, 31, this.loggingEnabled);
        Map<String, GBValue> map = this.savedGroups;
        int iHashCode = (this.trackingCallback.hashCode() + a.d((iG + (map == null ? 0 : map.hashCode())) * 31, 31, this.forcedVariations)) * 31;
        GBStickyBucketService gBStickyBucketService = this.stickyBucketService;
        int iHashCode2 = (iHashCode + (gBStickyBucketService == null ? 0 : gBStickyBucketService.hashCode())) * 31;
        Function2<String, GBFeatureResult, Unit> function2 = this.onFeatureUsage;
        return iHashCode2 + (function2 != null ? function2.hashCode() : 0);
    }

    public final void setForcedVariations(@NotNull Map<String, ? extends Object> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.forcedVariations = map;
    }

    @NotNull
    public String toString() {
        return "EvaluationContext(enabled=" + this.enabled + ", features=" + this.features + ", userContext=" + this.userContext + ", loggingEnabled=" + this.loggingEnabled + ", savedGroups=" + this.savedGroups + ", forcedVariations=" + this.forcedVariations + ", trackingCallback=" + this.trackingCallback + ", stickyBucketService=" + this.stickyBucketService + ", onFeatureUsage=" + this.onFeatureUsage + ')';
    }
}
