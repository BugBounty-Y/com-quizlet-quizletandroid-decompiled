package com.google.mlkit.vision.barcode;

import com.google.android.gms.common.internal.u;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class b {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof b) {
            return this.a == ((b) obj).a && u.l(null, null) && u.l(null, null);
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{Integer.valueOf(this.a), Boolean.FALSE, null, null});
    }
}
