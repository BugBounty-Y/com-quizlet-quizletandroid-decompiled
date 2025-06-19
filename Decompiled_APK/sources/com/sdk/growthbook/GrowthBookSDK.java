package com.sdk.growthbook;

import com.sdk.growthbook.evaluators.EvaluationContext;
import com.sdk.growthbook.evaluators.GBExperimentEvaluator;
import com.sdk.growthbook.evaluators.GBFeatureEvaluator;
import com.sdk.growthbook.evaluators.UserContext;
import com.sdk.growthbook.features.FeaturesDataModel;
import com.sdk.growthbook.features.FeaturesDataSource;
import com.sdk.growthbook.features.FeaturesFlowDelegate;
import com.sdk.growthbook.features.FeaturesViewModel;
import com.sdk.growthbook.model.GBContext;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBFeatureResult;
import com.sdk.growthbook.model.GBJson;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.network.NetworkDispatcher;
import com.sdk.growthbook.utils.Crypto;
import com.sdk.growthbook.utils.CryptoKt;
import com.sdk.growthbook.utils.GBError;
import com.sdk.growthbook.utils.GBRemoteEvalParams;
import com.sdk.growthbook.utils.GBUtils;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.v;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GrowthBookSDK implements FeaturesFlowDelegate {

    @NotNull
    public static final Companion Companion = new Companion(null);
    public static GBContext gbContext;

    @NotNull
    private Map<String, Pair<GBExperiment, GBExperimentResult>> assigned;

    @NotNull
    private Map<String, ? extends GBValue> attributeOverrides;
    private FeaturesViewModel featuresViewModel;

    @NotNull
    private Map<String, ? extends GBValue> forcedFeatures;
    private NetworkDispatcher networkDispatcher;
    private Function2<? super Boolean, ? super GBError, Unit> refreshHandler;
    private Map<String, ? extends GBValue> savedGroups;

    @NotNull
    private List<Function2<GBExperiment, GBExperimentResult, Unit>> subscriptions;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final GBContext getGbContext$GrowthBook_release() {
            GBContext gBContext = GrowthBookSDK.gbContext;
            if (gBContext != null) {
                return gBContext;
            }
            Intrinsics.m("gbContext");
            throw null;
        }

        public final void setGbContext$GrowthBook_release(@NotNull GBContext gBContext) {
            Intrinsics.checkNotNullParameter(gBContext, "<set-?>");
            GrowthBookSDK.gbContext = gBContext;
        }

        private Companion() {
        }
    }

    public GrowthBookSDK() {
        this.forcedFeatures = V.c();
        this.attributeOverrides = V.c();
        this.savedGroups = V.c();
        this.assigned = new LinkedHashMap();
        this.subscriptions = new ArrayList();
    }

    private final EvaluationContext createEvaluationContext() {
        Companion companion = Companion;
        return new EvaluationContext(companion.getGbContext$GrowthBook_release().getEnabled(), companion.getGbContext$GrowthBook_release().getFeatures$GrowthBook_release(), new UserContext(companion.getGbContext$GrowthBook_release().getQaMode(), companion.getGbContext$GrowthBook_release().getAttributes$GrowthBook_release(), companion.getGbContext$GrowthBook_release().getStickyBucketAssignmentDocs()), companion.getGbContext$GrowthBook_release().getEnableLogging(), companion.getGbContext$GrowthBook_release().getSavedGroups(), companion.getGbContext$GrowthBook_release().getForcedVariations(), companion.getGbContext$GrowthBook_release().getTrackingCallback(), companion.getGbContext$GrowthBook_release().getStickyBucketService(), companion.getGbContext$GrowthBook_release().getOnFeatureUsage());
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0029  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void fireSubscriptions(com.sdk.growthbook.model.GBExperiment r5, com.sdk.growthbook.model.GBExperimentResult r6) {
        /*
            r4 = this;
            java.lang.String r0 = r5.getKey()
            java.util.Map<java.lang.String, kotlin.Pair<com.sdk.growthbook.model.GBExperiment, com.sdk.growthbook.model.GBExperimentResult>> r1 = r4.assigned
            java.lang.Object r1 = r1.get(r0)
            kotlin.Pair r1 = (kotlin.Pair) r1
            if (r1 == 0) goto L29
            java.lang.Object r1 = r1.b
            r2 = r1
            com.sdk.growthbook.model.GBExperimentResult r2 = (com.sdk.growthbook.model.GBExperimentResult) r2
            boolean r2 = r2.getInExperiment()
            boolean r3 = r6.getInExperiment()
            if (r2 != r3) goto L29
            com.sdk.growthbook.model.GBExperimentResult r1 = (com.sdk.growthbook.model.GBExperimentResult) r1
            int r1 = r1.getVariationId()
            int r2 = r6.getVariationId()
            if (r1 == r2) goto L33
        L29:
            java.util.Map<java.lang.String, kotlin.Pair<com.sdk.growthbook.model.GBExperiment, com.sdk.growthbook.model.GBExperimentResult>> r1 = r4.assigned
            kotlin.Pair r2 = new kotlin.Pair
            r2.<init>(r5, r6)
            r1.put(r0, r2)
        L33:
            java.util.List<kotlin.jvm.functions.Function2<com.sdk.growthbook.model.GBExperiment, com.sdk.growthbook.model.GBExperimentResult, kotlin.Unit>> r0 = r4.subscriptions
            java.util.Iterator r0 = r0.iterator()
        L39:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L6e
            java.lang.Object r1 = r0.next()
            kotlin.jvm.functions.Function2 r1 = (kotlin.jvm.functions.Function2) r1
            r1.invoke(r5, r6)     // Catch: java.lang.Exception -> L49
            goto L39
        L49:
            r1 = move-exception
            com.sdk.growthbook.GrowthBookSDK$Companion r2 = com.sdk.growthbook.GrowthBookSDK.Companion
            com.sdk.growthbook.model.GBContext r2 = r2.getGbContext$GrowthBook_release()
            boolean r2 = r2.getEnableLogging()
            if (r2 == 0) goto L39
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            java.lang.String r3 = "Error while run subscriptions: "
            r2.<init>(r3)
            java.lang.String r1 = r1.getMessage()
            r2.append(r1)
            java.lang.String r1 = r2.toString()
            java.io.PrintStream r2 = java.lang.System.out
            r2.println(r1)
            goto L39
        L6e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.GrowthBookSDK.fireSubscriptions(com.sdk.growthbook.model.GBExperiment, com.sdk.growthbook.model.GBExperimentResult):void");
    }

    private final void refreshForRemoteEval() {
        Companion companion = Companion;
        if (companion.getGbContext$GrowthBook_release().getRemoteEval()) {
            GBRemoteEvalParams gBRemoteEvalParams = new GBRemoteEvalParams(companion.getGbContext$GrowthBook_release().getAttributes$GrowthBook_release(), this.forcedFeatures, companion.getGbContext$GrowthBook_release().getForcedVariations());
            FeaturesViewModel featuresViewModel = this.featuresViewModel;
            if (featuresViewModel != null) {
                featuresViewModel.fetchFeatures(companion.getGbContext$GrowthBook_release().getRemoteEval(), gBRemoteEvalParams);
            } else {
                Intrinsics.m("featuresViewModel");
                throw null;
            }
        }
    }

    private final void refreshStickyBucketService(FeaturesDataModel featuresDataModel) {
        Companion companion = Companion;
        if (companion.getGbContext$GrowthBook_release().getStickyBucketService() != null) {
            GBUtils.Companion.refreshStickyBuckets(companion.getGbContext$GrowthBook_release(), featuresDataModel, this.attributeOverrides);
        }
    }

    public static /* synthetic */ void refreshStickyBucketService$default(GrowthBookSDK growthBookSDK, FeaturesDataModel featuresDataModel, int i, Object obj) {
        if ((i & 1) != 0) {
            featuresDataModel = null;
        }
        growthBookSDK.refreshStickyBucketService(featuresDataModel);
    }

    @NotNull
    public final InterfaceC4992i autoRefreshFeatures() {
        FeaturesViewModel featuresViewModel = this.featuresViewModel;
        if (featuresViewModel != null) {
            return featuresViewModel.autoRefreshFeatures();
        }
        Intrinsics.m("featuresViewModel");
        throw null;
    }

    @NotNull
    public final GBFeatureResult feature(@NotNull String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        return GBFeatureEvaluator.evaluateFeature$default(new GBFeatureEvaluator(createEvaluationContext(), this.forcedFeatures), id, this.attributeOverrides, null, 4, null);
    }

    @Override // com.sdk.growthbook.features.FeaturesFlowDelegate
    public void featuresAPIModelSuccessfully(@NotNull FeaturesDataModel model) {
        Intrinsics.checkNotNullParameter(model, "model");
        refreshStickyBucketService(model);
    }

    @Override // com.sdk.growthbook.features.FeaturesFlowDelegate
    public void featuresFetchFailed(@NotNull GBError error, boolean z) {
        Function2<? super Boolean, ? super GBError, Unit> function2;
        Intrinsics.checkNotNullParameter(error, "error");
        if (!z || (function2 = this.refreshHandler) == null) {
            return;
        }
        function2.invoke(Boolean.FALSE, error);
    }

    @Override // com.sdk.growthbook.features.FeaturesFlowDelegate
    public void featuresFetchedSuccessfully(@NotNull Map<String, GBFeature> features, boolean z) {
        Function2<? super Boolean, ? super GBError, Unit> function2;
        Intrinsics.checkNotNullParameter(features, "features");
        Companion.getGbContext$GrowthBook_release().setFeatures$GrowthBook_release(features);
        if (!z || (function2 = this.refreshHandler) == null) {
            return;
        }
        function2.invoke(Boolean.TRUE, null);
    }

    @NotNull
    public final Map<String, Object> getAttributeOverrides() {
        return this.attributeOverrides;
    }

    @NotNull
    public final Map<String, GBFeature> getFeatures() {
        return Companion.getGbContext$GrowthBook_release().getFeatures$GrowthBook_release();
    }

    @NotNull
    public final Map<String, GBValue> getForcedFeatures() {
        return this.forcedFeatures;
    }

    @NotNull
    public final GBContext getGBContext() {
        return Companion.getGbContext$GrowthBook_release();
    }

    public final boolean isOn(@NotNull String featureId) {
        Intrinsics.checkNotNullParameter(featureId, "featureId");
        return feature(featureId).getOn();
    }

    public final void refreshCache() {
        if (Companion.getGbContext$GrowthBook_release().getRemoteEval()) {
            refreshForRemoteEval();
            return;
        }
        FeaturesViewModel featuresViewModel = this.featuresViewModel;
        if (featuresViewModel != null) {
            FeaturesViewModel.fetchFeatures$default(featuresViewModel, false, null, 3, null);
        } else {
            Intrinsics.m("featuresViewModel");
            throw null;
        }
    }

    @NotNull
    public final GBExperimentResult run(@NotNull GBExperiment experiment) {
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        GBExperimentResult gBExperimentResultEvaluateExperiment$default = GBExperimentEvaluator.evaluateExperiment$default(new GBExperimentEvaluator(createEvaluationContext()), experiment, this.attributeOverrides, null, 4, null);
        fireSubscriptions(experiment, gBExperimentResultEvaluateExperiment$default);
        return gBExperimentResultEvaluateExperiment$default;
    }

    @Override // com.sdk.growthbook.features.FeaturesFlowDelegate
    public void savedGroupsFetchFailed(@NotNull GBError error, boolean z) {
        Function2<? super Boolean, ? super GBError, Unit> function2;
        Intrinsics.checkNotNullParameter(error, "error");
        if (!z || (function2 = this.refreshHandler) == null) {
            return;
        }
        function2.invoke(Boolean.FALSE, error);
    }

    @Override // com.sdk.growthbook.features.FeaturesFlowDelegate
    public void savedGroupsFetchedSuccessfully(@NotNull v savedGroups, boolean z) {
        Function2<? super Boolean, ? super GBError, Unit> function2;
        Intrinsics.checkNotNullParameter(savedGroups, "savedGroups");
        GBContext gbContext$GrowthBook_release = Companion.getGbContext$GrowthBook_release();
        LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(savedGroups.size()));
        Iterator<T> it2 = savedGroups.entrySet().iterator();
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            linkedHashMap.put(entry.getKey(), GBValue.Companion.from$GrowthBook_release((k) entry.getValue()));
        }
        gbContext$GrowthBook_release.setSavedGroups(linkedHashMap);
        if (!z || (function2 = this.refreshHandler) == null) {
            return;
        }
        function2.invoke(Boolean.TRUE, null);
    }

    public final void setAttributeOverrides(@NotNull Map<String, ? extends GBValue> overrides) {
        Intrinsics.checkNotNullParameter(overrides, "overrides");
        this.attributeOverrides = overrides;
        if (Companion.getGbContext$GrowthBook_release().getStickyBucketService() != null) {
            refreshStickyBucketService$default(this, null, 1, null);
        }
        refreshForRemoteEval();
    }

    public final void setAttributes(@NotNull Map<String, ? extends GBValue> attributes) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Companion.getGbContext$GrowthBook_release().setAttributes$GrowthBook_release(attributes);
        refreshStickyBucketService$default(this, null, 1, null);
    }

    public final void setEncryptedFeatures(@NotNull String encryptedString, @NotNull String encryptionKey, Crypto crypto) {
        Intrinsics.checkNotNullParameter(encryptedString, "encryptedString");
        Intrinsics.checkNotNullParameter(encryptionKey, "encryptionKey");
        Map<String, GBFeature> featuresFromEncryptedFeatures = CryptoKt.getFeaturesFromEncryptedFeatures(encryptedString, encryptionKey, crypto);
        GBContext gbContext$GrowthBook_release = Companion.getGbContext$GrowthBook_release();
        if (featuresFromEncryptedFeatures == null) {
            return;
        }
        gbContext$GrowthBook_release.setFeatures$GrowthBook_release(featuresFromEncryptedFeatures);
    }

    public final void setForcedFeatures(@NotNull Map<String, ? extends GBValue> map) {
        Intrinsics.checkNotNullParameter(map, "<set-?>");
        this.forcedFeatures = map;
    }

    public final void setForcedVariations(@NotNull Map<String, ? extends Number> forcedVariations) {
        Intrinsics.checkNotNullParameter(forcedVariations, "forcedVariations");
        Companion.getGbContext$GrowthBook_release().setForcedVariations(forcedVariations);
        refreshForRemoteEval();
    }

    /* renamed from: feature, reason: collision with other method in class */
    public final <V> V m25feature(String id) {
        Intrinsics.checkNotNullParameter(id, "id");
        B.j(K.a(Boolean.TYPE), K.a(String.class), K.a(Number.class), K.a(Short.TYPE), K.a(Integer.TYPE), K.a(Long.TYPE), K.a(Float.TYPE), K.a(Double.TYPE), K.a(GBJson.class));
        throw new UnsupportedOperationException("This function has a reified type parameter and thus can only be inlined at compilation time, not called directly.");
    }

    public /* synthetic */ GrowthBookSDK(GBContext gBContext, Function2 function2, NetworkDispatcher networkDispatcher, Map map, Map map2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(gBContext, function2, networkDispatcher, (i & 8) != 0 ? null : map, (i & 16) != 0 ? null : map2);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public GrowthBookSDK(@NotNull GBContext context, Function2<? super Boolean, ? super GBError, Unit> function2, @NotNull NetworkDispatcher networkDispatcher, Map<String, GBFeature> map, Map<String, ? extends GBValue> map2) {
        this();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(networkDispatcher, "networkDispatcher");
        Companion companion = Companion;
        companion.setGbContext$GrowthBook_release(context);
        this.refreshHandler = function2;
        this.networkDispatcher = networkDispatcher;
        this.featuresViewModel = new FeaturesViewModel(this, new FeaturesDataSource(networkDispatcher, context.getEnableLogging()), companion.getGbContext$GrowthBook_release().getEncryptionKey());
        if (map != null) {
            companion.getGbContext$GrowthBook_release().setFeatures$GrowthBook_release(map);
        } else {
            refreshCache();
        }
        this.savedGroups = map2;
        refreshStickyBucketService$default(this, null, 1, null);
    }
}
