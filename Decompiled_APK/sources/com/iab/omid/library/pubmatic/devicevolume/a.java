package com.iab.omid.library.pubmatic.devicevolume;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public class a {
    public float a(int i, int i2) {
        if (i2 <= 0 || i <= 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = i / i2;
        if (f > 1.0f) {
            return 1.0f;
        }
        return f;
    }
}
