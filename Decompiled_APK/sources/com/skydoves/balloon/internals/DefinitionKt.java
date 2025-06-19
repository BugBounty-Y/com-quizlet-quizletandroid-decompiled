package com.skydoves.balloon.internals;

import com.skydoves.balloon.annotations.InternalBalloonApi;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class DefinitionKt {
    public static final int LTR = 1;
    public static final float NO_Float_VALUE = 0.0f;
    public static final int NO_INT_VALUE = Integer.MIN_VALUE;
    public static final long NO_LONG_VALUE = -1;
    public static final int SIZE_ARROW_BOUNDARY = 1;

    @InternalBalloonApi
    public static /* synthetic */ void getNO_Float_VALUE$annotations() {
    }

    public static final /* synthetic */ Integer takeIfNotNoIntValue(int i) {
        Integer numValueOf = Integer.valueOf(i);
        if (i != Integer.MIN_VALUE) {
            return numValueOf;
        }
        return null;
    }

    public static final /* synthetic */ int unaryMinus(int i, boolean z) {
        return z ? -i : i;
    }
}
