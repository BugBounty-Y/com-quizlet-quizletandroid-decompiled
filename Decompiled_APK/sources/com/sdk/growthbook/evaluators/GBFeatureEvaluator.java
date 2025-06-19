package com.sdk.growthbook.evaluators;

import com.sdk.growthbook.model.FeatureEvalContext;
import com.sdk.growthbook.model.GBBoolean;
import com.sdk.growthbook.model.GBExperiment;
import com.sdk.growthbook.model.GBExperimentResult;
import com.sdk.growthbook.model.GBFeatureResult;
import com.sdk.growthbook.model.GBFeatureSource;
import com.sdk.growthbook.model.GBNumber;
import com.sdk.growthbook.model.GBValue;
import java.util.LinkedHashSet;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBFeatureEvaluator {

    @NotNull
    private final EvaluationContext evaluationContext;

    @NotNull
    private final Map<String, Object> forcedFeature;

    public GBFeatureEvaluator(@NotNull EvaluationContext evaluationContext, @NotNull Map<String, ? extends Object> forcedFeature) {
        Intrinsics.checkNotNullParameter(evaluationContext, "evaluationContext");
        Intrinsics.checkNotNullParameter(forcedFeature, "forcedFeature");
        this.evaluationContext = evaluationContext;
        this.forcedFeature = forcedFeature;
    }

    public static /* synthetic */ GBFeatureResult evaluateFeature$default(GBFeatureEvaluator gBFeatureEvaluator, String str, Map map, FeatureEvalContext featureEvalContext, int i, Object obj) {
        if ((i & 4) != 0) {
            featureEvalContext = new FeatureEvalContext(str, new LinkedHashSet());
        }
        return gBFeatureEvaluator.evaluateFeature(str, map, featureEvalContext);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private final Map<String, GBValue> getAttributes(Map<String, ? extends GBValue> map, Map<String, ? extends GBValue> map2) {
        V.m(map).putAll(map2);
        return map;
    }

    private final GBFeatureResult prepareResult(String str, GBValue gBValue, GBFeatureSource gBFeatureSource, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult) {
        boolean z = true;
        boolean z2 = (gBValue instanceof GBBoolean) && !((GBBoolean) gBValue).getValue();
        boolean z3 = (gBValue instanceof GBNumber) && Intrinsics.b(((GBNumber) gBValue).getValue(), 0);
        if (gBValue != null && !z2 && !z3) {
            z = false;
        }
        GBFeatureResult gBFeatureResult = new GBFeatureResult(gBValue, !z, z, gBFeatureSource, gBExperiment, gBExperimentResult);
        Function2<String, GBFeatureResult, Unit> onFeatureUsage = this.evaluationContext.getOnFeatureUsage();
        if (onFeatureUsage != null) {
            onFeatureUsage.invoke(str, gBFeatureResult);
        }
        return gBFeatureResult;
    }

    public static /* synthetic */ GBFeatureResult prepareResult$default(GBFeatureEvaluator gBFeatureEvaluator, String str, GBValue gBValue, GBFeatureSource gBFeatureSource, GBExperiment gBExperiment, GBExperimentResult gBExperimentResult, int i, Object obj) {
        if ((i & 8) != 0) {
            gBExperiment = null;
        }
        if ((i & 16) != 0) {
            gBExperimentResult = null;
        }
        return gBFeatureEvaluator.prepareResult(str, gBValue, gBFeatureSource, gBExperiment, gBExperimentResult);
    }

    /* JADX WARN: Removed duplicated region for block: B:65:0x0180 A[Catch: Exception -> 0x038a, TryCatch #1 {Exception -> 0x038a, blocks: (B:3:0x0019, B:5:0x0022, B:7:0x002a, B:8:0x0049, B:10:0x0051, B:11:0x0057, B:13:0x0064, B:15:0x006c, B:16:0x0073, B:18:0x007d, B:20:0x008a, B:22:0x00a4, B:25:0x00ac, B:26:0x00b0, B:28:0x00b6, B:36:0x00f8, B:40:0x0103, B:45:0x0122, B:48:0x0128, B:55:0x0156, B:63:0x017a, B:65:0x0180, B:68:0x019b, B:72:0x01a7, B:74:0x01c8, B:77:0x01ce, B:78:0x01d7, B:94:0x0210, B:102:0x023b, B:103:0x0243, B:105:0x0249, B:107:0x0262, B:111:0x027a, B:113:0x0280, B:116:0x0288, B:118:0x029a, B:121:0x02a2, B:124:0x02aa, B:126:0x02ba, B:128:0x02c0, B:134:0x02dc, B:137:0x02e6, B:139:0x02ef, B:143:0x02f8, B:145:0x035a, B:147:0x0366, B:150:0x0376), top: B:157:0x0019 }] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x019b A[Catch: Exception -> 0x038a, TRY_LEAVE, TryCatch #1 {Exception -> 0x038a, blocks: (B:3:0x0019, B:5:0x0022, B:7:0x002a, B:8:0x0049, B:10:0x0051, B:11:0x0057, B:13:0x0064, B:15:0x006c, B:16:0x0073, B:18:0x007d, B:20:0x008a, B:22:0x00a4, B:25:0x00ac, B:26:0x00b0, B:28:0x00b6, B:36:0x00f8, B:40:0x0103, B:45:0x0122, B:48:0x0128, B:55:0x0156, B:63:0x017a, B:65:0x0180, B:68:0x019b, B:72:0x01a7, B:74:0x01c8, B:77:0x01ce, B:78:0x01d7, B:94:0x0210, B:102:0x023b, B:103:0x0243, B:105:0x0249, B:107:0x0262, B:111:0x027a, B:113:0x0280, B:116:0x0288, B:118:0x029a, B:121:0x02a2, B:124:0x02aa, B:126:0x02ba, B:128:0x02c0, B:134:0x02dc, B:137:0x02e6, B:139:0x02ef, B:143:0x02f8, B:145:0x035a, B:147:0x0366, B:150:0x0376), top: B:157:0x0019 }] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01e4 A[Catch: Exception -> 0x02e1, TRY_ENTER, TryCatch #2 {Exception -> 0x02e1, blocks: (B:70:0x01a1, B:81:0x01e4, B:85:0x01f1, B:89:0x0200, B:92:0x020a, B:97:0x0217, B:100:0x0235, B:109:0x0274, B:132:0x02ce), top: B:158:0x01a1 }] */
    @org.jetbrains.annotations.NotNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.sdk.growthbook.model.GBFeatureResult evaluateFeature(@org.jetbrains.annotations.NotNull java.lang.String r38, @org.jetbrains.annotations.NotNull java.util.Map<java.lang.String, ? extends com.sdk.growthbook.model.GBValue> r39, @org.jetbrains.annotations.NotNull com.sdk.growthbook.model.FeatureEvalContext r40) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 923
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.evaluators.GBFeatureEvaluator.evaluateFeature(java.lang.String, java.util.Map, com.sdk.growthbook.model.FeatureEvalContext):com.sdk.growthbook.model.GBFeatureResult");
    }

    public /* synthetic */ GBFeatureEvaluator(EvaluationContext evaluationContext, Map map, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(evaluationContext, (i & 2) != 0 ? V.c() : map);
    }
}
