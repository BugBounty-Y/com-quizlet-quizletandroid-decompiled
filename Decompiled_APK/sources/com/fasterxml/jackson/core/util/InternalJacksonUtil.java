package com.fasterxml.jackson.core.util;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;

/* loaded from: classes.dex */
public abstract class InternalJacksonUtil {
    public static int addOverflowSafe(int i, int i2) {
        int i3 = i + i2;
        return i3 < 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i3;
    }
}
