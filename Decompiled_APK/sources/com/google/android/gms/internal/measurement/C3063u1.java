package com.google.android.gms.internal.measurement;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.measurement.u1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3063u1 {
    public final Context a;
    public final com.google.common.base.l b;

    public C3063u1(Context context, com.google.common.base.l lVar) {
        this.a = context;
        this.b = lVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C3063u1) {
            C3063u1 c3063u1 = (C3063u1) obj;
            if (this.a.equals(c3063u1.a)) {
                com.google.common.base.l lVar = c3063u1.b;
                com.google.common.base.l lVar2 = this.b;
                if (lVar2 != null ? lVar2.equals(lVar) : lVar == null) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() ^ 1000003;
        com.google.common.base.l lVar = this.b;
        return (iHashCode * 1000003) ^ (lVar == null ? 0 : lVar.hashCode());
    }

    public final String toString() {
        return AbstractC0147y.e("FlagsContext{context=", this.a.toString(), ", hermeticFileOverrides=", String.valueOf(this.b), "}");
    }
}
