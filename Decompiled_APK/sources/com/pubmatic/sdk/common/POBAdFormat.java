package com.pubmatic.sdk.common;

import androidx.annotation.Keep;
import java.util.Arrays;
import kotlin.Metadata;

@Keep
@Metadata
/* loaded from: classes2.dex */
public enum POBAdFormat {
    BANNER,
    MREC,
    INTERSTITIAL,
    REWARDEDAD,
    NATIVE;

    /* renamed from: values, reason: to resolve conflict with enum method */
    public static POBAdFormat[] valuesCustom() {
        POBAdFormat[] pOBAdFormatArrValuesCustom = values();
        return (POBAdFormat[]) Arrays.copyOf(pOBAdFormatArrValuesCustom, pOBAdFormatArrValuesCustom.length);
    }
}
