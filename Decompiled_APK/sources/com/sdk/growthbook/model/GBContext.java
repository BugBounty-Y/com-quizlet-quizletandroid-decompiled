package com.sdk.growthbook.model;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import com.sdk.growthbook.stickybucket.GBStickyBucketService;
import com.sdk.growthbook.utils.GBStickyAssignmentsDocument;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBContext {

    @NotNull
    private final String apiKey;

    @NotNull
    private Map<String, ? extends GBValue> attributes;
    private final boolean enableLogging;
    private final boolean enabled;
    private final String encryptionKey;

    @NotNull
    private Map<String, GBFeature> features;

    @NotNull
    private Map<String, ? extends Number> forcedVariations;

    @NotNull
    private final String hostURL;
    private final Function2<String, GBFeatureResult, Unit> onFeatureUsage;
    private final boolean qaMode;
    private final boolean remoteEval;
    private Map<String, ? extends GBValue> savedGroups;
    private Map<String, GBStickyAssignmentsDocument> stickyBucketAssignmentDocs;
    private List<String> stickyBucketIdentifierAttributes;
    private final GBStickyBucketService stickyBucketService;

    @NotNull
    private final Function2<GBExperiment, GBExperimentResult, Unit> trackingCallback;

    /* JADX WARN: Multi-variable type inference failed */
    public GBContext(@NotNull String apiKey, @NotNull String hostURL, boolean z, String str, @NotNull Map<String, ? extends GBValue> attributes, @NotNull Map<String, ? extends Number> forcedVariations, Map<String, GBStickyAssignmentsDocument> map, List<String> list, GBStickyBucketService gBStickyBucketService, boolean z2, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, Function2<? super String, ? super GBFeatureResult, Unit> function2, boolean z3, boolean z4, Map<String, ? extends GBValue> map2) {
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(hostURL, "hostURL");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        this.apiKey = apiKey;
        this.hostURL = hostURL;
        this.enabled = z;
        this.encryptionKey = str;
        this.attributes = attributes;
        this.forcedVariations = forcedVariations;
        this.stickyBucketAssignmentDocs = map;
        this.stickyBucketIdentifierAttributes = list;
        this.stickyBucketService = gBStickyBucketService;
        this.qaMode = z2;
        this.trackingCallback = trackingCallback;
        this.onFeatureUsage = function2;
        this.remoteEval = z3;
        this.enableLogging = z4;
        this.savedGroups = map2;
        this.features = new HashMap();
    }

    @NotNull
    public final String component1() {
        return this.apiKey;
    }

    public final boolean component10() {
        return this.qaMode;
    }

    @NotNull
    public final Function2<GBExperiment, GBExperimentResult, Unit> component11() {
        return this.trackingCallback;
    }

    public final Function2<String, GBFeatureResult, Unit> component12() {
        return this.onFeatureUsage;
    }

    public final boolean component13() {
        return this.remoteEval;
    }

    public final boolean component14() {
        return this.enableLogging;
    }

    public final Map<String, GBValue> component15() {
        return this.savedGroups;
    }

    @NotNull
    public final String component2() {
        return this.hostURL;
    }

    public final boolean component3() {
        return this.enabled;
    }

    public final String component4() {
        return this.encryptionKey;
    }

    @NotNull
    public final Map<String, GBValue> component5$GrowthBook_release() {
        return this.attributes;
    }

    @NotNull
    public final Map<String, Number> component6() {
        return this.forcedVariations;
    }

    public final Map<String, GBStickyAssignmentsDocument> component7() {
        return this.stickyBucketAssignmentDocs;
    }

    public final List<String> component8() {
        return this.stickyBucketIdentifierAttributes;
    }

    public final GBStickyBucketService component9() {
        return this.stickyBucketService;
    }

    @NotNull
    public final GBContext copy(@NotNull String apiKey, @NotNull String hostURL, boolean z, String str, @NotNull Map<String, ? extends GBValue> attributes, @NotNull Map<String, ? extends Number> forcedVariations, Map<String, GBStickyAssignmentsDocument> map, List<String> list, GBStickyBucketService gBStickyBucketService, boolean z2, @NotNull Function2<? super GBExperiment, ? super GBExperimentResult, Unit> trackingCallback, Function2<? super String, ? super GBFeatureResult, Unit> function2, boolean z3, boolean z4, Map<String, ? extends GBValue> map2) {
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        Intrinsics.checkNotNullParameter(hostURL, "hostURL");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        Intrinsics.checkNotNullParameter(trackingCallback, "trackingCallback");
        return new GBContext(apiKey, hostURL, z, str, attributes, forcedVariations, map, list, gBStickyBucketService, z2, trackingCallback, function2, z3, z4, map2);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GBContext)) {
            return false;
        }
        GBContext gBContext = (GBContext) obj;
        return Intrinsics.b(this.apiKey, gBContext.apiKey) && Intrinsics.b(this.hostURL, gBContext.hostURL) && this.enabled == gBContext.enabled && Intrinsics.b(this.encryptionKey, gBContext.encryptionKey) && Intrinsics.b(this.attributes, gBContext.attributes) && Intrinsics.b(this.forcedVariations, gBContext.forcedVariations) && Intrinsics.b(this.stickyBucketAssignmentDocs, gBContext.stickyBucketAssignmentDocs) && Intrinsics.b(this.stickyBucketIdentifierAttributes, gBContext.stickyBucketIdentifierAttributes) && Intrinsics.b(this.stickyBucketService, gBContext.stickyBucketService) && this.qaMode == gBContext.qaMode && Intrinsics.b(this.trackingCallback, gBContext.trackingCallback) && Intrinsics.b(this.onFeatureUsage, gBContext.onFeatureUsage) && this.remoteEval == gBContext.remoteEval && this.enableLogging == gBContext.enableLogging && Intrinsics.b(this.savedGroups, gBContext.savedGroups);
    }

    @NotNull
    public final String getApiKey() {
        return this.apiKey;
    }

    @NotNull
    public final Map<String, GBValue> getAttributes$GrowthBook_release() {
        return this.attributes;
    }

    public final boolean getEnableLogging() {
        return this.enableLogging;
    }

    public final boolean getEnabled() {
        return this.enabled;
    }

    public final String getEncryptionKey() {
        return this.encryptionKey;
    }

    @NotNull
    public final Map<String, GBFeature> getFeatures$GrowthBook_release() {
        return this.features;
    }

    @NotNull
    public final Map<String, Number> getForcedVariations() {
        return this.forcedVariations;
    }

    @NotNull
    public final String getHostURL() {
        return this.hostURL;
    }

    public final Function2<String, GBFeatureResult, Unit> getOnFeatureUsage() {
        return this.onFeatureUsage;
    }

    public final boolean getQaMode() {
        return this.qaMode;
    }

    public final boolean getRemoteEval() {
        return this.remoteEval;
    }

    public final Map<String, GBValue> getSavedGroups() {
        return this.savedGroups;
    }

    public final Map<String, GBStickyAssignmentsDocument> getStickyBucketAssignmentDocs() {
        return this.stickyBucketAssignmentDocs;
    }

    public final List<String> getStickyBucketIdentifierAttributes() {
        return this.stickyBucketIdentifierAttributes;
    }

    public final GBStickyBucketService getStickyBucketService() {
        return this.stickyBucketService;
    }

    @NotNull
    public final Function2<GBExperiment, GBExperimentResult, Unit> getTrackingCallback() {
        return this.trackingCallback;
    }

    public int hashCode() {
        int iG = d0.g(d0.e(this.apiKey.hashCode() * 31, 31, this.hostURL), 31, this.enabled);
        String str = this.encryptionKey;
        int iD = a.d(a.d((iG + (str == null ? 0 : str.hashCode())) * 31, 31, this.attributes), 31, this.forcedVariations);
        Map<String, GBStickyAssignmentsDocument> map = this.stickyBucketAssignmentDocs;
        int iHashCode = (iD + (map == null ? 0 : map.hashCode())) * 31;
        List<String> list = this.stickyBucketIdentifierAttributes;
        int iHashCode2 = (iHashCode + (list == null ? 0 : list.hashCode())) * 31;
        GBStickyBucketService gBStickyBucketService = this.stickyBucketService;
        int iHashCode3 = (this.trackingCallback.hashCode() + d0.g((iHashCode2 + (gBStickyBucketService == null ? 0 : gBStickyBucketService.hashCode())) * 31, 31, this.qaMode)) * 31;
        Function2<String, GBFeatureResult, Unit> function2 = this.onFeatureUsage;
        int iG2 = d0.g(d0.g((iHashCode3 + (function2 == null ? 0 : function2.hashCode())) * 31, 31, this.remoteEval), 31, this.enableLogging);
        Map<String, ? extends GBValue> map2 = this.savedGroups;
        return iG2 + (map2 != null ? map2.hashCode() : 0);
    }

    public final void setAttributes$GrowthBook_release(@NotNull Map<String, ? extends GBValue> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.attributes = map;
    }

    public final void setFeatures$GrowthBook_release(@NotNull Map<String, GBFeature> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.features = map;
    }

    public final void setForcedVariations(@NotNull Map<String, ? extends Number> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.forcedVariations = map;
    }

    public final void setSavedGroups(Map<String, ? extends GBValue> map) {
        this.savedGroups = map;
    }

    public final void setStickyBucketAssignmentDocs(Map<String, GBStickyAssignmentsDocument> map) {
        this.stickyBucketAssignmentDocs = map;
    }

    public final void setStickyBucketIdentifierAttributes(List<String> list) {
        this.stickyBucketIdentifierAttributes = list;
    }

    @NotNull
    public String toString() {
        return "GBContext(apiKey=" + this.apiKey + ", hostURL=" + this.hostURL + ", enabled=" + this.enabled + ", encryptionKey=" + this.encryptionKey + ", attributes=" + this.attributes + ", forcedVariations=" + this.forcedVariations + ", stickyBucketAssignmentDocs=" + this.stickyBucketAssignmentDocs + ", stickyBucketIdentifierAttributes=" + this.stickyBucketIdentifierAttributes + ", stickyBucketService=" + this.stickyBucketService + ", qaMode=" + this.qaMode + ", trackingCallback=" + this.trackingCallback + ", onFeatureUsage=" + this.onFeatureUsage + ", remoteEval=" + this.remoteEval + ", enableLogging=" + this.enableLogging + ", savedGroups=" + this.savedGroups + ')';
    }

    public /* synthetic */ GBContext(String str, String str2, boolean z, String str3, Map map, Map map2, Map map3, List list, GBStickyBucketService gBStickyBucketService, boolean z2, Function2 function2, Function2 function22, boolean z3, boolean z4, Map map4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, z, str3, map, map2, (i & 64) != 0 ? null : map3, (i & 128) != 0 ? null : list, (i & 256) != 0 ? null : gBStickyBucketService, z2, function2, (i & 2048) != 0 ? null : function22, (i & 4096) != 0 ? false : z3, (i & 8192) != 0 ? false : z4, (i & 16384) != 0 ? null : map4);
    }
}
