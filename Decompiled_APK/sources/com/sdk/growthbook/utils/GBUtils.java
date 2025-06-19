package com.sdk.growthbook.utils;

import com.ionspin.kotlin.bignum.integer.c;
import com.pubmatic.sdk.video.c;
import com.sdk.growthbook.evaluators.EvaluationContext;
import com.sdk.growthbook.evaluators.UserContext;
import com.sdk.growthbook.features.FeaturesDataModel;
import com.sdk.growthbook.model.GBContext;
import com.sdk.growthbook.model.GBFeature;
import com.sdk.growthbook.model.GBFeatureRule;
import com.sdk.growthbook.model.GBString;
import com.sdk.growthbook.model.GBValue;
import com.sdk.growthbook.stickybucket.GBStickyBucketService;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.collections.V;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;
import kotlin.text.D;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import kotlin.v;
import kotlinx.serialization.json.d;
import kotlinx.serialization.json.internal.JsonDecodingException;
import kotlinx.serialization.json.internal.x;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.l;
import kotlinx.serialization.json.y;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBUtils {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private final List<String> deriveStickyBucketIdentifierAttributes(GBContext gBContext, FeaturesDataModel featuresDataModel) {
            Map<String, GBFeature> features$GrowthBook_release;
            List<GBFeatureRule> rules;
            LinkedHashSet linkedHashSet = new LinkedHashSet();
            if (featuresDataModel == null || (features$GrowthBook_release = featuresDataModel.getFeatures()) == null) {
                features$GrowthBook_release = gBContext.getFeatures$GrowthBook_release();
            }
            Iterator<T> it2 = features$GrowthBook_release.keySet().iterator();
            while (it2.hasNext()) {
                GBFeature gBFeature = features$GrowthBook_release.get((String) it2.next());
                if (gBFeature != null && (rules = gBFeature.getRules()) != null) {
                    for (GBFeatureRule gBFeatureRule : rules) {
                        if (gBFeatureRule.getVariations() != null) {
                            String hashAttribute = gBFeatureRule.getHashAttribute();
                            if (hashAttribute == null) {
                                hashAttribute = "id";
                            }
                            linkedHashSet.add(hashAttribute);
                            String fallbackAttribute = gBFeatureRule.getFallbackAttribute();
                            if (fallbackAttribute != null) {
                                linkedHashSet.add(fallbackAttribute);
                            }
                        }
                    }
                }
            }
            return CollectionsKt.w0(linkedHashSet);
        }

        public static /* synthetic */ Pair getHashAttribute$default(Companion companion, String str, String str2, Map map, Map map2, int i, Object obj) {
            if ((i & 2) != 0) {
                str2 = null;
            }
            return companion.getHashAttribute(str, str2, map, map2);
        }

        private final Map<String, String> getStickyBucketAssignments(UserContext userContext, String str, String str2, Map<String, ? extends GBValue> map, Map<String, ? extends GBValue> map2) {
            GBStickyAssignmentsDocument gBStickyAssignmentsDocument;
            k kVarGbSerialize$GrowthBook_release;
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            Map<String, GBStickyAssignmentsDocument> stickyBucketAssignmentDocs$GrowthBook_release = userContext.getStickyBucketAssignmentDocs$GrowthBook_release();
            if (stickyBucketAssignmentDocs$GrowthBook_release != null) {
                String strA = null;
                Pair<String, String> hashAttribute = getHashAttribute(str, null, map, map2);
                String strL = android.support.v4.media.session.a.l((String) hashAttribute.a, "||", (String) hashAttribute.b);
                Pair<String, String> hashAttribute2 = getHashAttribute(null, str2, map, map2);
                String str3 = (String) hashAttribute2.a;
                String str4 = (String) hashAttribute2.b;
                String strL2 = str4.length() == 0 ? null : android.support.v4.media.session.a.l(str3, "||", str4);
                StringBuilder sbX = android.support.v4.media.session.a.x(str2, "||");
                sbX.append(toHashValue(map2.get(str2)));
                GBStickyAssignmentsDocument gBStickyAssignmentsDocument2 = stickyBucketAssignmentDocs$GrowthBook_release.get(sbX.toString());
                String attributeValue = gBStickyAssignmentsDocument2 != null ? gBStickyAssignmentsDocument2.getAttributeValue() : null;
                GBValue gBValue = map2.get(str2);
                if (gBValue != null && (kVarGbSerialize$GrowthBook_release = gBValue.gbSerialize$GrowthBook_release()) != null) {
                    strA = l.h(kVarGbSerialize$GrowthBook_release).a();
                }
                if (!Intrinsics.b(attributeValue, strA)) {
                    userContext.setStickyBucketAssignmentDocs$GrowthBook_release(V.c());
                }
                if (strL2 != null && (gBStickyAssignmentsDocument = stickyBucketAssignmentDocs$GrowthBook_release.get(strL2)) != null) {
                    linkedHashMap.putAll(gBStickyAssignmentsDocument.getAssignments());
                }
                GBStickyAssignmentsDocument gBStickyAssignmentsDocument3 = stickyBucketAssignmentDocs$GrowthBook_release.get(strL);
                if (gBStickyAssignmentsDocument3 != null) {
                    linkedHashMap.putAll(gBStickyAssignmentsDocument3.getAssignments());
                }
            }
            return linkedHashMap;
        }

        private final Map<String, String> getStickyBucketAttributes(GBContext gBContext, FeaturesDataModel featuresDataModel, Map<String, ? extends GBValue> map) {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            List<String> stickyBucketIdentifierAttributes = gBContext.getStickyBucketIdentifierAttributes();
            if (stickyBucketIdentifierAttributes == null) {
                stickyBucketIdentifierAttributes = deriveStickyBucketIdentifierAttributes(gBContext, featuresDataModel);
            }
            gBContext.setStickyBucketIdentifierAttributes(stickyBucketIdentifierAttributes);
            List<String> stickyBucketIdentifierAttributes2 = gBContext.getStickyBucketIdentifierAttributes();
            if (stickyBucketIdentifierAttributes2 != null) {
                for (String str : stickyBucketIdentifierAttributes2) {
                    Map<String, ? extends GBValue> map2 = map;
                    linkedHashMap.put(str, getHashAttribute$default(GBUtils.Companion, str, null, gBContext.getAttributes$GrowthBook_release(), map2, 2, null).b);
                    map = map2;
                }
            }
            return linkedHashMap;
        }

        public static /* synthetic */ String getStickyBucketExperimentKey$default(Companion companion, String str, int i, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                i = 0;
            }
            return companion.getStickyBucketExperimentKey(str, i);
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static Pair getStickyBucketVariation$default(Companion companion, String str, UserContext userContext, int i, int i2, List list, String str2, String str3, Map map, int i3, Object obj) {
            if ((i3 & 4) != 0) {
                i = 0;
            }
            if ((i3 & 8) != 0) {
                i2 = 0;
            }
            if ((i3 & 16) != 0) {
                list = K.a;
            }
            if ((i3 & 32) != 0) {
                str2 = null;
            }
            if ((i3 & 64) != 0) {
                str3 = "id";
            }
            return companion.getStickyBucketVariation(str, userContext, i, i2, list, str2, str3, map);
        }

        private final float hashV1(String str, String str2) {
            return Float.parseFloat(new FNV().fnv1a32(str + str2).m(new c(1000)).p()) / 1000.0f;
        }

        private final float hashV2(String str, String str2) {
            return Float.parseFloat(new FNV().fnv1a32(new FNV().fnv1a32(str2 + str).p()).m(new c(c.a.DEFAULT_MEDIA_URI_TIMEOUT)).p()) / 10000.0f;
        }

        private final boolean inRange(Float f, Pair<Float, Float> pair) {
            return f != null && pair != null && f.floatValue() >= ((Number) pair.a).floatValue() && f.floatValue() < ((Number) pair.b).floatValue();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final CharSequence paddedVersionString$lambda$3(String it2) {
            Intrinsics.checkNotNullParameter(it2, "it");
            return new Regex("^\\d+$").e(it2) ? StringsKt.S(' ', 5, it2) : it2;
        }

        private final float roundTo(float f, int i) {
            return kotlin.math.c.b(f * r6) / ((float) Math.pow(10.0f, i));
        }

        private final String toHashValue(GBValue gBValue) {
            if (gBValue instanceof GBString) {
                return ((GBString) gBValue).getValue();
            }
            return String.valueOf(gBValue != null ? gBValue.gbSerialize$GrowthBook_release() : null);
        }

        public final int chooseVariation(float f, @NotNull List<Pair<Float, Float>> ranges) {
            Intrinsics.checkNotNullParameter(ranges, "ranges");
            Iterator<T> it2 = ranges.iterator();
            int i = 0;
            while (it2.hasNext()) {
                int i2 = i + 1;
                if (inRange(Float.valueOf(f), (Pair) it2.next())) {
                    return i;
                }
                i = i2;
            }
            return -1;
        }

        public final Object convertToPrimitiveIfPossible(Object obj) {
            Object objE;
            if (obj instanceof y) {
                y yVar = (y) obj;
                Integer numG = l.g(yVar);
                if (numG != null) {
                    return numG;
                }
                Intrinsics.checkNotNullParameter(yVar, "<this>");
                Boolean bool = null;
                try {
                    objE = Long.valueOf(l.i(yVar));
                } catch (JsonDecodingException unused) {
                    objE = null;
                }
                if (objE == null) {
                    Intrinsics.checkNotNullParameter(yVar, "<this>");
                    objE = C.e(yVar.a());
                    if (objE == null && (objE = l.f(yVar)) == null) {
                        Intrinsics.checkNotNullParameter(yVar, "<this>");
                        String strA = yVar.a();
                        String[] strArr = x.a;
                        Intrinsics.checkNotNullParameter(strA, "<this>");
                        if (D.l(strA, "true", true)) {
                            bool = Boolean.TRUE;
                        } else if (D.l(strA, "false", true)) {
                            bool = Boolean.FALSE;
                        }
                        if (bool != null) {
                            return bool;
                        }
                        String strE = l.e(yVar);
                        if (strE != null) {
                            return strE;
                        }
                    }
                }
                return objE;
            }
            return obj;
        }

        @NotNull
        public final v generateStickyBucketAssignmentDoc(@NotNull String attributeName, @NotNull String attributeValue, @NotNull Map<String, String> assignments, Map<String, GBStickyAssignmentsDocument> map) {
            Map<String, String> mapC;
            GBStickyAssignmentsDocument gBStickyAssignmentsDocument;
            Intrinsics.checkNotNullParameter(attributeName, "attributeName");
            Intrinsics.checkNotNullParameter(attributeValue, "attributeValue");
            Intrinsics.checkNotNullParameter(assignments, "assignments");
            StringBuilder sb = new StringBuilder();
            sb.append(attributeName);
            String strT = android.support.v4.media.session.a.t(sb, "||", attributeValue);
            if (map == null || (gBStickyAssignmentsDocument = map.get(strT)) == null || (mapC = gBStickyAssignmentsDocument.getAssignments()) == null) {
                mapC = V.c();
            }
            LinkedHashMap linkedHashMapM = V.m(mapC);
            linkedHashMapM.putAll(assignments);
            return new v(strT, new GBStickyAssignmentsDocument(attributeName, attributeValue, linkedHashMapM), Boolean.valueOf(!mapC.equals(linkedHashMapM)));
        }

        @NotNull
        public final List<Pair<Float, Float>> getBucketRanges(int i, float f, List<Float> list) {
            float f2 = DefinitionKt.NO_Float_VALUE;
            float f3 = f < DefinitionKt.NO_Float_VALUE ? 0.0f : f;
            if (f > 1.0f) {
                f3 = 1.0f;
            }
            List<Float> equalWeights = getEqualWeights(i);
            if (list == null) {
                list = equalWeights;
            }
            if (list.size() == i) {
                equalWeights = list;
            }
            Iterator<T> it2 = equalWeights.iterator();
            if (!it2.hasNext()) {
                throw new UnsupportedOperationException("Empty collection can't be reduced.");
            }
            Object next = it2.next();
            while (it2.hasNext()) {
                next = Float.valueOf(((Number) next).floatValue() + ((Number) it2.next()).floatValue());
            }
            double dFloatValue = ((Number) next).floatValue();
            if (dFloatValue < 0.99d || dFloatValue > 1.01d) {
                equalWeights = getEqualWeights(i);
            }
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(equalWeights, 10));
            Iterator<T> it3 = equalWeights.iterator();
            while (it3.hasNext()) {
                float fFloatValue = ((Number) it3.next()).floatValue();
                Companion companion = GBUtils.Companion;
                arrayList.add(new Pair(Float.valueOf(companion.roundTo(f2, 4)), Float.valueOf(companion.roundTo((fFloatValue * f3) + f2, 4))));
                f2 += fFloatValue;
            }
            return arrayList;
        }

        @NotNull
        public final List<Float> getEqualWeights(int i) {
            if (i <= 0) {
                return K.a;
            }
            float f = 1.0f / i;
            ArrayList arrayList = new ArrayList(i);
            for (int i2 = 0; i2 < i; i2++) {
                arrayList.add(Float.valueOf(f));
            }
            return arrayList;
        }

        public final v getGBNameSpace(@NotNull d namespace) {
            Intrinsics.checkNotNullParameter(namespace, "namespace");
            if (namespace.a.size() < 3) {
                return null;
            }
            String strE = l.e(l.h(namespace.get(0)));
            Float f = l.f(l.h(namespace.get(1)));
            Float f2 = l.f(l.h(namespace.get(2)));
            if (strE == null || f == null || f2 == null) {
                return null;
            }
            return new v(strE, f, f2);
        }

        /* JADX WARN: Removed duplicated region for block: B:24:0x0062 A[PHI: r0
  0x0062: PHI (r0v9 java.lang.String) = (r0v8 java.lang.String), (r0v8 java.lang.String), (r0v12 java.lang.String) binds: [B:13:0x0036, B:14:0x0038, B:22:0x005f] A[DONT_GENERATE, DONT_INLINE]] */
        @org.jetbrains.annotations.NotNull
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final kotlin.Pair<java.lang.String, java.lang.String> getHashAttribute(java.lang.String r3, java.lang.String r4, @org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, ? extends com.sdk.growthbook.model.GBValue> r5, @org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, ? extends com.sdk.growthbook.model.GBValue> r6) {
            /*
                r2 = this;
                java.lang.String r0 = "attributes"
                kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
                java.lang.String r0 = "attributeOverrides"
                kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
                if (r3 != 0) goto Le
                java.lang.String r3 = "id"
            Le:
                java.lang.Object r0 = r6.get(r3)
                if (r0 == 0) goto L1f
                java.lang.Object r0 = r6.get(r3)
                com.sdk.growthbook.model.GBValue r0 = (com.sdk.growthbook.model.GBValue) r0
                java.lang.String r0 = r2.toHashValue(r0)
                goto L32
            L1f:
                java.lang.Object r0 = r5.get(r3)
                if (r0 == 0) goto L30
                java.lang.Object r0 = r5.get(r3)
                com.sdk.growthbook.model.GBValue r0 = (com.sdk.growthbook.model.GBValue) r0
                java.lang.String r0 = r2.toHashValue(r0)
                goto L32
            L30:
                java.lang.String r0 = ""
            L32:
                int r1 = r0.length()
                if (r1 != 0) goto L62
                if (r4 == 0) goto L62
                java.lang.Object r1 = r6.get(r4)
                if (r1 == 0) goto L4b
                java.lang.Object r5 = r6.get(r4)
                com.sdk.growthbook.model.GBValue r5 = (com.sdk.growthbook.model.GBValue) r5
                java.lang.String r0 = r2.toHashValue(r5)
                goto L5b
            L4b:
                java.lang.Object r6 = r5.get(r4)
                if (r6 == 0) goto L5b
                java.lang.Object r5 = r5.get(r4)
                com.sdk.growthbook.model.GBValue r5 = (com.sdk.growthbook.model.GBValue) r5
                java.lang.String r0 = r2.toHashValue(r5)
            L5b:
                int r5 = r0.length()
                if (r5 <= 0) goto L62
                goto L63
            L62:
                r4 = r3
            L63:
                kotlin.Pair r3 = new kotlin.Pair
                r3.<init>(r4, r0)
                return r3
            */
            throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.utils.GBUtils.Companion.getHashAttribute(java.lang.String, java.lang.String, java.util.Map, java.util.Map):kotlin.Pair");
        }

        @NotNull
        public final String getStickyBucketExperimentKey(@NotNull String experimentKey, int i) {
            Intrinsics.checkNotNullParameter(experimentKey, "experimentKey");
            return experimentKey + "__" + i;
        }

        @NotNull
        public final Pair<Integer, Boolean> getStickyBucketVariation(@NotNull String experimentKey, @NotNull UserContext userContext, int i, int i2, @NotNull List<GBVariationMeta> meta, String str, String str2, @NotNull Map<String, ? extends GBValue> attributeOverrides) {
            Intrinsics.checkNotNullParameter(experimentKey, "experimentKey");
            Intrinsics.checkNotNullParameter(userContext, "userContext");
            Intrinsics.checkNotNullParameter(meta, "meta");
            Intrinsics.checkNotNullParameter(attributeOverrides, "attributeOverrides");
            String stickyBucketExperimentKey = getStickyBucketExperimentKey(experimentKey, i);
            Map<String, String> stickyBucketAssignments = getStickyBucketAssignments(userContext, str2, str, userContext.getAttributes$GrowthBook_release(), attributeOverrides);
            int i3 = 0;
            int i4 = -1;
            if (i2 > 0 && i2 >= 0) {
                for (int i5 = 0; !stickyBucketAssignments.containsKey(getStickyBucketExperimentKey(experimentKey, i5)); i5++) {
                    if (i5 != i2) {
                    }
                }
                return new Pair<>(-1, Boolean.TRUE);
            }
            String str3 = stickyBucketAssignments.get(stickyBucketExperimentKey);
            if (str3 == null) {
                return new Pair<>(-1, null);
            }
            Iterator<GBVariationMeta> it2 = meta.iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                if (Intrinsics.b(it2.next().getKey(), str3)) {
                    i4 = i3;
                    break;
                }
                i3++;
            }
            return i4 >= 0 ? new Pair<>(Integer.valueOf(i4), null) : new Pair<>(-1, null);
        }

        public final Float hash(@NotNull String stringValue, Integer num, String str) {
            Intrinsics.checkNotNullParameter(stringValue, "stringValue");
            if (num == null) {
                return null;
            }
            if (num.intValue() == 1) {
                return Float.valueOf(hashV1(stringValue, str));
            }
            if (num.intValue() == 2) {
                return Float.valueOf(hashV2(stringValue, str));
            }
            return null;
        }

        public final boolean inNamespace(@NotNull String userId, @NotNull v namespace) {
            Intrinsics.checkNotNullParameter(userId, "userId");
            Intrinsics.checkNotNullParameter(namespace, "namespace");
            Float fHash = hash(userId + "__", 1, (String) namespace.a);
            if (fHash != null) {
                return inRange(fHash, new Pair<>(namespace.b, namespace.c));
            }
            return false;
        }

        public final boolean isFilteredOut(List<GBFilter> list, Map<String, ? extends GBValue> map, @NotNull EvaluationContext evaluationContext) {
            Intrinsics.checkNotNullParameter(evaluationContext, "evaluationContext");
            if (list == null || map == null || list.isEmpty()) {
                return false;
            }
            for (GBFilter gBFilter : list) {
                String attribute = gBFilter.getAttribute();
                if (attribute == null) {
                    attribute = "id";
                }
                GBValue gBValue = (GBValue) V.d(attribute, evaluationContext.getUserContext().getAttributes$GrowthBook_release());
                if ((gBValue instanceof GBValue.Unknown) || !(gBValue.gbSerialize$GrowthBook_release() instanceof y)) {
                    return true;
                }
                Companion companion = GBUtils.Companion;
                String hashValue = companion.toHashValue(gBValue);
                if (hashValue.length() == 0) {
                    return true;
                }
                Integer hashVersion = gBFilter.getHashVersion();
                Float fHash = companion.hash(hashValue, Integer.valueOf(hashVersion != null ? hashVersion.intValue() : 2), gBFilter.getSeed());
                if (fHash == null) {
                    return true;
                }
                List<Pair<Float, Float>> ranges = gBFilter.getRanges();
                if (ranges != null && ranges.isEmpty()) {
                    return true;
                }
                Iterator<T> it2 = ranges.iterator();
                while (it2.hasNext()) {
                    if (GBUtils.Companion.inRange(fHash, (Pair) it2.next())) {
                        break;
                    }
                }
                return true;
            }
            return false;
        }

        public final boolean isIncludedInRollout(@NotNull Map<String, ? extends GBValue> attributes, @NotNull Map<String, ? extends GBValue> attributeOverrides, String str, String str2, String str3, Pair<Float, Float> pair, Float f, Integer num) {
            Intrinsics.checkNotNullParameter(attributes, "attributes");
            Intrinsics.checkNotNullParameter(attributeOverrides, "attributeOverrides");
            if (pair == null && f == null) {
                return true;
            }
            Float fHash = hash((String) getHashAttribute(str2, str3, attributes, attributeOverrides).b, Integer.valueOf(num != null ? num.intValue() : 1), str);
            if (fHash != null) {
                return pair != null ? inRange(fHash, pair) : f == null || fHash.floatValue() <= f.floatValue();
            }
            return false;
        }

        @NotNull
        public final String paddedVersionString(@NotNull String input) {
            List list;
            Intrinsics.checkNotNullParameter(input, "input");
            List listG = new Regex("[-.]").g(0, new Regex("^v|\\+.*$").replace(input, ""));
            if (listG.size() == 3) {
                ArrayList arrayList = new ArrayList(listG);
                arrayList.add("~");
                list = arrayList;
            } else {
                list = listG;
            }
            return CollectionsKt.S(list, "-", null, null, new a(0), 30);
        }

        public final void refreshStickyBuckets(@NotNull GBContext context, FeaturesDataModel featuresDataModel, @NotNull Map<String, ? extends GBValue> attributeOverrides) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(attributeOverrides, "attributeOverrides");
            GBStickyBucketService stickyBucketService = context.getStickyBucketService();
            if (stickyBucketService == null) {
                return;
            }
            context.setStickyBucketAssignmentDocs(stickyBucketService.getAllAssignments(getStickyBucketAttributes(context, featuresDataModel, attributeOverrides)));
        }

        private Companion() {
        }
    }
}
