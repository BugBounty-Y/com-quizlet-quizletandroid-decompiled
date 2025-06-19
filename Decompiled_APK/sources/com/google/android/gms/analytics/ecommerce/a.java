package com.google.android.gms.analytics.ecommerce;

import com.google.android.gms.analytics.f;
import com.google.android.gms.common.internal.u;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class a {
    public final HashMap a = new HashMap();

    public final HashMap a(String str) {
        HashMap map = new HashMap();
        for (Map.Entry entry : this.a.entrySet()) {
            String strValueOf = String.valueOf((String) entry.getKey());
            map.put(str.concat(strValueOf), (String) entry.getValue());
        }
        return map;
    }

    public final void b(String str, String str2) {
        u.i(str, "Name should be non-null");
        this.a.put(str, str2);
    }

    public final String toString() {
        return f.zzb(this.a);
    }
}
