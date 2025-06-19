package com.sdk.growthbook.evaluators;

import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeatureResult;
import com.sdk.growthbook.model.GBFeatureSource;
import com.sdk.growthbook.model.GBJson;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.utils.GBParentConditionInterface;
import com.sdk.growthbook.utils.GBStickyAssignmentsDocument;
import com.sdk.growthbook.utils.GBUtils;
import com.sdk.growthbook.utils.GBVariationMeta;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.K;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;
import kotlinx.serialization.internal.G;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBExperimentEvaluator {

    @NotNull
    private final EvaluationContext evaluationContext;

    public GBExperimentEvaluator(@NotNull EvaluationContext evaluationContext) {
        Intrinsics.checkNotNullParameter(evaluationContext, "evaluationContext");
        this.evaluationContext = evaluationContext;
    }

    public static /* synthetic */ GBExperimentResult evaluateExperiment$default(GBExperimentEvaluator gBExperimentEvaluator, GBExperiment gBExperiment, Map map, String str, int i, Object obj) {
        if ((i & 4) != 0) {
            str = null;
        }
        return gBExperimentEvaluator.evaluateExperiment(gBExperiment, map, str);
    }

    private final GBExperimentResult getExperimentResult(GBExperiment gBExperiment, int i, boolean z, String str, Float f, Boolean bool, Map<String, ? extends GBValue> map) {
        boolean z2;
        int i2;
        String strValueOf;
        if (i < 0 || i >= gBExperiment.getVariations().size()) {
            z2 = false;
            i2 = 0;
        } else {
            i2 = i;
            z2 = true;
        }
        Pair<String, String> hashAttribute = GBUtils.Companion.getHashAttribute(gBExperiment.getHashAttribute(), (this.evaluationContext.getStickyBucketService() == null || Intrinsics.b(gBExperiment.getDisableStickyBucketing(), Boolean.TRUE)) ? null : gBExperiment.getFallBackAttribute(), this.evaluationContext.getUserContext().getAttributes$GrowthBook_release(), map);
        String str2 = (String) hashAttribute.a;
        String str3 = (String) hashAttribute.b;
        List meta = gBExperiment.getMeta();
        if (meta == null) {
            meta = K.a;
        }
        GBVariationMeta gBVariationMeta = meta.size() > i2 ? (GBVariationMeta) meta.get(i2) : null;
        GBValue gBValue = i2 < gBExperiment.getVariations().size() ? gBExperiment.getVariations().get(i2) : GBValue.Unknown.INSTANCE;
        if (gBVariationMeta == null || (strValueOf = gBVariationMeta.getKey()) == null) {
            strValueOf = String.valueOf(i2);
        }
        return new GBExperimentResult(z2, i2, gBValue, str2, str3, strValueOf, gBVariationMeta != null ? gBVariationMeta.getName() : null, f, gBVariationMeta != null ? gBVariationMeta.getPassthrough() : null, Boolean.valueOf(z), str, Boolean.valueOf(bool != null ? bool.booleanValue() : false));
    }

    public static /* synthetic */ GBExperimentResult getExperimentResult$default(GBExperimentEvaluator gBExperimentEvaluator, GBExperiment gBExperiment, int i, boolean z, String str, Float f, Boolean bool, Map map, int i2, Object obj) {
        Boolean bool2;
        GBExperimentEvaluator gBExperimentEvaluator2;
        GBExperiment gBExperiment2;
        boolean z2;
        Map map2;
        if ((i2 & 2) != 0) {
            i = 0;
        }
        int i3 = i;
        String str2 = (i2 & 8) != 0 ? null : str;
        Float f2 = (i2 & 16) != 0 ? null : f;
        if ((i2 & 32) != 0) {
            bool2 = null;
            gBExperiment2 = gBExperiment;
            z2 = z;
            map2 = map;
            gBExperimentEvaluator2 = gBExperimentEvaluator;
        } else {
            bool2 = bool;
            gBExperimentEvaluator2 = gBExperimentEvaluator;
            gBExperiment2 = gBExperiment;
            z2 = z;
            map2 = map;
        }
        return gBExperimentEvaluator2.getExperimentResult(gBExperiment2, i3, z2, str2, f2, bool2, map2);
    }

    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [java.util.Map, kotlin.jvm.internal.DefaultConstructorMarker] */
    /* JADX WARN: Type inference failed for: r10v3 */
    @NotNull
    public final GBExperimentResult evaluateExperiment(@NotNull GBExperiment experiment, @NotNull Map<String, ? extends GBValue> attributeOverrides, String str) throws Throwable {
        GBUtils.Companion companion;
        int iChooseVariation;
        boolean zBooleanValue;
        boolean z;
        GBExperimentEvaluator gBExperimentEvaluator;
        v gBNameSpace;
        Map<String, ? extends GBValue> mapC;
        Intrinsics.checkNotNullParameter(experiment, "experiment");
        Intrinsics.checkNotNullParameter(attributeOverrides, "attributeOverrides");
        int i = 2;
        if (experiment.getVariations().size() < 2 || !this.evaluationContext.getEnabled()) {
            return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        Object obj = this.evaluationContext.getForcedVariations().get(experiment.getKey());
        if (obj != null) {
            return getExperimentResult$default(this, experiment, Integer.parseInt(obj.toString()), false, str, null, null, attributeOverrides, 48, null);
        }
        if (Intrinsics.b(experiment.getActive(), Boolean.FALSE)) {
            return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        GBUtils.Companion companion2 = GBUtils.Companion;
        ?? r10 = 0;
        Pair<String, String> hashAttribute = companion2.getHashAttribute(experiment.getHashAttribute(), (this.evaluationContext.getStickyBucketService() == null || Intrinsics.b(experiment.getDisableStickyBucketing(), Boolean.TRUE)) ? null : experiment.getFallBackAttribute(), this.evaluationContext.getUserContext().getAttributes$GrowthBook_release(), attributeOverrides);
        String str2 = (String) hashAttribute.a;
        String str3 = (String) hashAttribute.b;
        if (str3.length() == 0 || str3.equals("null")) {
            return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        if (this.evaluationContext.getStickyBucketService() == null || Intrinsics.b(experiment.getDisableStickyBucketing(), Boolean.TRUE)) {
            companion = companion2;
            iChooseVariation = -1;
            zBooleanValue = false;
            z = false;
        } else {
            companion = companion2;
            String key = experiment.getKey();
            UserContext userContext = this.evaluationContext.getUserContext();
            Integer bucketVersion = experiment.getBucketVersion();
            int iIntValue = bucketVersion != null ? bucketVersion.intValue() : 0;
            Integer minBucketVersion = experiment.getMinBucketVersion();
            int iIntValue2 = minBucketVersion != null ? minBucketVersion.intValue() : 0;
            List<GBVariationMeta> meta = experiment.getMeta();
            if (meta == null) {
                meta = K.a;
            }
            Pair<Integer, Boolean> stickyBucketVariation = companion.getStickyBucketVariation(key, userContext, iIntValue, iIntValue2, meta, experiment.getFallBackAttribute(), experiment.getHashAttribute(), attributeOverrides);
            iChooseVariation = ((Number) stickyBucketVariation.a).intValue();
            Boolean bool = (Boolean) stickyBucketVariation.b;
            z = iChooseVariation >= 0;
            zBooleanValue = bool != null ? bool.booleanValue() : false;
        }
        if (z) {
            gBExperimentEvaluator = this;
        } else {
            if (experiment.getFilters() != null) {
                if (companion.isFilteredOut(experiment.getFilters(), this.evaluationContext.getUserContext().getAttributes$GrowthBook_release(), this.evaluationContext)) {
                    if (this.evaluationContext.getLoggingEnabled()) {
                        System.out.println((Object) "Skip because of filters");
                    }
                    return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
                }
            } else if (experiment.getNamespace() != null && (gBNameSpace = companion.getGBNameSpace(experiment.getNamespace())) != null && !companion.inNamespace(str3, gBNameSpace)) {
                return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
            }
            gBExperimentEvaluator = this;
            if (experiment.getCondition() != null) {
                Map<String, GBValue> attributes$GrowthBook_release = gBExperimentEvaluator.evaluationContext.getUserContext().getAttributes$GrowthBook_release();
                k condition = experiment.getCondition();
                Intrinsics.d(condition);
                GBValue gBValueFrom$GrowthBook_release = GBValue.Companion.from$GrowthBook_release(condition);
                GBJson gBJson = gBValueFrom$GrowthBook_release instanceof GBJson ? (GBJson) gBValueFrom$GrowthBook_release : null;
                if (gBJson == null) {
                    gBJson = new GBJson(V.c());
                }
                if (!new GBConditionEvaluator().evalCondition(attributes$GrowthBook_release, gBJson, gBExperimentEvaluator.evaluationContext.getSavedGroups())) {
                    return getExperimentResult$default(gBExperimentEvaluator, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
                }
            }
            if (experiment.getParentConditions() != null) {
                Iterator<GBParentConditionInterface> it2 = experiment.getParentConditions().iterator();
                Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                while (it2.hasNext()) {
                    GBParentConditionInterface next = it2.next();
                    Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                    GBParentConditionInterface gBParentConditionInterface = next;
                    GBFeatureEvaluator gBFeatureEvaluator = new GBFeatureEvaluator(gBExperimentEvaluator.evaluationContext, r10, i, r10);
                    String id = gBParentConditionInterface.getId();
                    k condition2 = gBParentConditionInterface.getCondition();
                    G g = l.a;
                    Intrinsics.checkNotNullParameter(condition2, "<this>");
                    kotlinx.serialization.json.v vVar = condition2 instanceof kotlinx.serialization.json.v ? (kotlinx.serialization.json.v) condition2 : r10;
                    if (vVar == null) {
                        Throwable th = r10;
                        l.d("JsonObject", condition2);
                        throw th;
                    }
                    Map map = vVar.a;
                    LinkedHashMap linkedHashMap = new LinkedHashMap(U.a(map.size()));
                    GBJson gBJson2 = r10;
                    for (Map.Entry entry : map.entrySet()) {
                        linkedHashMap.put(entry.getKey(), GBValue.Companion.from$GrowthBook_release((k) entry.getValue()));
                        gBJson2 = gBJson2;
                    }
                    GBJson gBJson3 = gBJson2;
                    GBFeatureResult gBFeatureResultEvaluateFeature$default = GBFeatureEvaluator.evaluateFeature$default(gBFeatureEvaluator, id, linkedHashMap, null, 4, null);
                    if (gBFeatureResultEvaluateFeature$default.getSource() == GBFeatureSource.cyclicPrerequisite) {
                        return getExperimentResult$default(gBExperimentEvaluator, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
                    }
                    GBValue gbValue = gBFeatureResultEvaluateFeature$default.getGbValue();
                    if (gbValue == null || (mapC = U.b(new Pair("value", gbValue))) == null) {
                        mapC = V.c();
                    }
                    GBValue gBValueFrom$GrowthBook_release2 = GBValue.Companion.from$GrowthBook_release(gBParentConditionInterface.getCondition());
                    GBJson gBJson4 = gBValueFrom$GrowthBook_release2 instanceof GBJson ? (GBJson) gBValueFrom$GrowthBook_release2 : gBJson3;
                    if (gBJson4 == null) {
                        gBJson4 = new GBJson(V.c());
                    }
                    if (!new GBConditionEvaluator().evalCondition(mapC, gBJson4, gBExperimentEvaluator.evaluationContext.getSavedGroups())) {
                        if (gBExperimentEvaluator.evaluationContext.getLoggingEnabled()) {
                            System.out.println((Object) "Feature blocked by prerequisite");
                        }
                        return getExperimentResult$default(gBExperimentEvaluator, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
                    }
                    r10 = gBJson3;
                    i = 2;
                }
            }
        }
        GBUtils.Companion companion3 = GBUtils.Companion;
        Integer hashVersion = experiment.getHashVersion();
        Integer numValueOf = Integer.valueOf(hashVersion != null ? hashVersion.intValue() : 1);
        String seed = experiment.getSeed();
        if (seed == null) {
            seed = experiment.getKey();
        }
        Float fHash = companion3.hash(str3, numValueOf, seed);
        if (fHash == null) {
            if (gBExperimentEvaluator.evaluationContext.getLoggingEnabled()) {
                System.out.println((Object) "Skip because of invalid hash version");
            }
            return getExperimentResult$default(gBExperimentEvaluator, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        if (!z) {
            List<Pair<Float, Float>> ranges = experiment.getRanges();
            if (ranges == null) {
                int size = experiment.getVariations().size();
                Float coverage = experiment.getCoverage();
                float fFloatValue = coverage != null ? coverage.floatValue() : 1.0f;
                List<Float> weights = experiment.getWeights();
                if (weights == null) {
                    weights = K.a;
                }
                ranges = companion3.getBucketRanges(size, fFloatValue, weights);
            }
            iChooseVariation = companion3.chooseVariation(fHash.floatValue(), ranges);
        }
        if (zBooleanValue) {
            if (gBExperimentEvaluator.evaluationContext.getLoggingEnabled()) {
                System.out.println((Object) "Skip because sticky bucket version is blocked");
            }
            return gBExperimentEvaluator.getExperimentResult(experiment, -1, false, str, null, Boolean.TRUE, attributeOverrides);
        }
        if (iChooseVariation < 0) {
            if (gBExperimentEvaluator.evaluationContext.getLoggingEnabled()) {
                System.out.println((Object) "Skip because of coverage");
            }
            return getExperimentResult$default(gBExperimentEvaluator, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        Integer force = experiment.getForce();
        if (force != null) {
            return getExperimentResult$default(this, experiment, force.intValue(), false, str, null, null, attributeOverrides, 48, null);
        }
        if (this.evaluationContext.getUserContext().getQaMode()) {
            return getExperimentResult$default(this, experiment, -1, false, str, null, null, attributeOverrides, 48, null);
        }
        GBExperimentResult experimentResult = getExperimentResult(experiment, iChooseVariation, true, str, fHash, Boolean.valueOf(z), attributeOverrides);
        if (this.evaluationContext.getLoggingEnabled()) {
            System.out.println((Object) ("ExperimentResult: " + experimentResult));
        }
        if (this.evaluationContext.getStickyBucketService() != null && !Intrinsics.b(experiment.getDisableStickyBucketing(), Boolean.TRUE)) {
            Map<String, GBStickyAssignmentsDocument> stickyBucketAssignmentDocs$GrowthBook_release = this.evaluationContext.getUserContext().getStickyBucketAssignmentDocs$GrowthBook_release();
            String key2 = experiment.getKey();
            Integer bucketVersion2 = experiment.getBucketVersion();
            v vVarGenerateStickyBucketAssignmentDoc = companion3.generateStickyBucketAssignmentDoc(str2, str3, U.b(new Pair(companion3.getStickyBucketExperimentKey(key2, bucketVersion2 != null ? bucketVersion2.intValue() : 0), experimentResult.getKey())), stickyBucketAssignmentDocs$GrowthBook_release);
            String str4 = (String) vVarGenerateStickyBucketAssignmentDoc.a;
            GBStickyAssignmentsDocument gBStickyAssignmentsDocument = (GBStickyAssignmentsDocument) vVarGenerateStickyBucketAssignmentDoc.b;
            if (((Boolean) vVarGenerateStickyBucketAssignmentDoc.c).booleanValue()) {
                UserContext userContext2 = this.evaluationContext.getUserContext();
                if (stickyBucketAssignmentDocs$GrowthBook_release == null) {
                    stickyBucketAssignmentDocs$GrowthBook_release = V.c();
                }
                LinkedHashMap linkedHashMapM = V.m(stickyBucketAssignmentDocs$GrowthBook_release);
                linkedHashMapM.put(str4, gBStickyAssignmentsDocument);
                userContext2.setStickyBucketAssignmentDocs$GrowthBook_release(linkedHashMapM);
                this.evaluationContext.getStickyBucketService().saveAssignments(gBStickyAssignmentsDocument);
            }
        }
        if (!this.evaluationContext.getExperimentHelper$GrowthBook_release().isTracked(experiment, experimentResult)) {
            this.evaluationContext.getTrackingCallback().invoke(experiment, experimentResult);
        }
        return experimentResult;
    }
}
