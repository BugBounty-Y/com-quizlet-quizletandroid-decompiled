package com.sdk.growthbook.serializable_model;

import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class SerializableGBFeatureRuleKt {
    /* JADX WARN: Removed duplicated region for block: B:22:0x00c5  */
    @org.jetbrains.annotations.NotNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final com.sdk.growthbook.model.GBFeatureRule gbDeserialize(@org.jetbrains.annotations.NotNull com.sdk.growthbook.serializable_model.SerializableGBFeatureRule r26) {
        /*
            java.lang.String r0 = "<this>"
            r1 = r26
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r0)
            java.lang.String r2 = r1.getId()
            java.lang.String r8 = r1.getKey()
            java.util.ArrayList r15 = r1.getMeta()
            java.lang.String r17 = r1.getSeed()
            java.lang.String r18 = r1.getName()
            kotlin.Pair r13 = r1.getRange()
            java.lang.String r19 = r1.getPhase()
            java.util.List r14 = r1.getRanges()
            java.util.ArrayList r0 = r1.getTracks()
            r3 = 10
            r4 = 0
            if (r0 == 0) goto L5d
            java.util.ArrayList r0 = r1.getTracks()
            java.util.ArrayList r5 = new java.util.ArrayList
            int r6 = kotlin.collections.C.q(r0, r3)
            r5.<init>(r6)
            java.util.Iterator r0 = r0.iterator()
        L41:
            boolean r6 = r0.hasNext()
            if (r6 == 0) goto L55
            java.lang.Object r6 = r0.next()
            com.sdk.growthbook.serializable_model.SerializableGBTrackData r6 = (com.sdk.growthbook.serializable_model.SerializableGBTrackData) r6
            com.sdk.growthbook.utils.GBTrackData r6 = com.sdk.growthbook.serializable_model.SerializableGBTrackDataKt.gbDeserialize(r6)
            r5.add(r6)
            goto L41
        L55:
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>(r5)
            r24 = r0
            goto L5f
        L5d:
            r24 = r4
        L5f:
            java.util.ArrayList r16 = r1.getFilters()
            java.util.List r9 = r1.getWeights()
            java.lang.Float r5 = r1.getCoverage()
            kotlinx.serialization.json.d r10 = r1.getNamespace()
            kotlinx.serialization.json.k r0 = r1.getCondition()
            java.lang.Integer r12 = r1.getHashVersion()
            java.lang.Integer r22 = r1.getBucketVersion()
            java.lang.String r11 = r1.getHashAttribute()
            r6 = r4
            java.util.ArrayList r4 = r1.getParentConditions()
            java.lang.Integer r23 = r1.getMinBucketVersion()
            java.lang.String r20 = r1.getFallbackAttribute()
            com.sdk.growthbook.utils.OptionalProperty r7 = r1.getForce()
            boolean r6 = r7 instanceof com.sdk.growthbook.utils.OptionalProperty.Present
            if (r6 == 0) goto Lb6
            com.sdk.growthbook.utils.OptionalProperty r6 = r1.getForce()
            com.sdk.growthbook.utils.OptionalProperty$Present r6 = (com.sdk.growthbook.utils.OptionalProperty.Present) r6
            java.lang.Object r6 = r6.getValue()
            if (r6 != 0) goto La3
        La0:
            r6 = 0
        La1:
            r7 = 0
            goto Lbb
        La3:
            com.sdk.growthbook.model.GBValue$Companion r6 = com.sdk.growthbook.model.GBValue.Companion
            com.sdk.growthbook.utils.OptionalProperty r7 = r1.getForce()
            com.sdk.growthbook.utils.OptionalProperty$Present r7 = (com.sdk.growthbook.utils.OptionalProperty.Present) r7
            java.lang.Object r7 = r7.getValue()
            kotlinx.serialization.json.k r7 = (kotlinx.serialization.json.k) r7
            com.sdk.growthbook.model.GBValue r6 = r6.from$GrowthBook_release(r7)
            goto La1
        Lb6:
            boolean r6 = r7 instanceof com.sdk.growthbook.utils.OptionalProperty.NotPresent
            if (r6 == 0) goto Lf6
            goto La0
        Lbb:
            java.lang.Boolean r21 = r1.getDisableStickyBucketing()
            java.util.List r1 = r1.getVariations()
            if (r1 == 0) goto Lec
            java.util.ArrayList r7 = new java.util.ArrayList
            int r3 = kotlin.collections.C.q(r1, r3)
            r7.<init>(r3)
            java.util.Iterator r1 = r1.iterator()
        Ld2:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto Lec
            java.lang.Object r3 = r1.next()
            kotlinx.serialization.json.k r3 = (kotlinx.serialization.json.k) r3
            r25 = r0
            com.sdk.growthbook.model.GBValue$Companion r0 = com.sdk.growthbook.model.GBValue.Companion
            com.sdk.growthbook.model.GBValue r0 = r0.from$GrowthBook_release(r3)
            r7.add(r0)
            r0 = r25
            goto Ld2
        Lec:
            r25 = r0
            com.sdk.growthbook.model.GBFeatureRule r1 = new com.sdk.growthbook.model.GBFeatureRule
            r3 = r25
            r1.<init>(r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, r24)
            return r1
        Lf6:
            kotlin.NoWhenBranchMatchedException r0 = new kotlin.NoWhenBranchMatchedException
            r0.<init>()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.sdk.growthbook.serializable_model.SerializableGBFeatureRuleKt.gbDeserialize(com.sdk.growthbook.serializable_model.SerializableGBFeatureRule):com.sdk.growthbook.model.GBFeatureRule");
    }
}
