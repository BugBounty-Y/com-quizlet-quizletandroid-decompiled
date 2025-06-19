package com.google.android.gms.auth.api;

import androidx.work.impl.model.l;
import com.google.android.gms.common.internal.u;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class c implements com.google.android.gms.common.api.b {
    public static final c c;
    public final boolean a;
    public final String b;

    static {
        l lVar = new l(9);
        lVar.b = Boolean.FALSE;
        c = new c(lVar);
    }

    public c(l lVar) {
        this.a = ((Boolean) lVar.b).booleanValue();
        this.b = (String) lVar.c;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        cVar.getClass();
        return u.l(null, null) && this.a == cVar.a && u.l(this.b, cVar.b);
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{null, Boolean.valueOf(this.a), this.b});
    }
}
