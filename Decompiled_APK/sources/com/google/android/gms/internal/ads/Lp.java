package com.google.android.gms.internal.ads;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class Lp {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && Lp.class == obj.getClass()) {
            if (Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Float.floatToIntBits(DefinitionKt.NO_Float_VALUE) + 16337;
    }
}
