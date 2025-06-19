package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3536t3;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.measurement.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C3012k implements InterfaceC3027n, InterfaceC3007j {
    public final HashMap a = new HashMap();

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final boolean M(String str) {
        return this.a.containsKey(str);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final InterfaceC3027n a(String str) {
        HashMap map = this.a;
        return map.containsKey(str) ? (InterfaceC3027n) map.get(str) : InterfaceC3027n.Q0;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final void b(String str, InterfaceC3027n interfaceC3027n) {
        HashMap map = this.a;
        if (interfaceC3027n == null) {
            map.remove(str);
        } else {
            map.put(str, interfaceC3027n);
        }
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        return "toString".equals(str) ? new C3042q(toString()) : AbstractC3536t3.a(this, new C3042q(str), c1721Kc, arrayList);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C3012k) {
            return this.a.equals(((C3012k) obj).a);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        return Double.valueOf(Double.NaN);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        return Boolean.TRUE;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        C3012k c3012k = new C3012k();
        for (Map.Entry entry : this.a.entrySet()) {
            boolean z = entry.getValue() instanceof InterfaceC3007j;
            HashMap map = c3012k.a;
            if (z) {
                map.put((String) entry.getKey(), (InterfaceC3027n) entry.getValue());
            } else {
                map.put((String) entry.getKey(), ((InterfaceC3027n) entry.getValue()).j());
            }
        }
        return c3012k;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return new C3002i(this.a.keySet().iterator());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("{");
        HashMap map = this.a;
        if (!map.isEmpty()) {
            for (String str : map.keySet()) {
                sb.append(String.format("%s: %s,", str, map.get(str)));
            }
            sb.deleteCharAt(sb.lastIndexOf(","));
        }
        sb.append("}");
        return sb.toString();
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        return "[object Object]";
    }
}
