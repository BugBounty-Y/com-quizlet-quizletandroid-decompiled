package com.google.android.gms.common.api.internal;

import com.google.android.gms.common.Feature;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class o {
    public final C1643a a;
    public final Feature b;

    public /* synthetic */ o(C1643a c1643a, Feature feature) {
        this.a = c1643a;
        this.b = feature;
    }

    public final boolean equals(Object obj) {
        if (obj != null && (obj instanceof o)) {
            o oVar = (o) obj;
            if (com.google.android.gms.common.internal.u.l(this.a, oVar.a) && com.google.android.gms.common.internal.u.l(this.b, oVar.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, this.b});
    }

    public final String toString() {
        androidx.compose.foundation.text.input.internal.u uVar = new androidx.compose.foundation.text.input.internal.u(this);
        uVar.b(this.a, "key");
        uVar.b(this.b, "feature");
        return uVar.toString();
    }
}
