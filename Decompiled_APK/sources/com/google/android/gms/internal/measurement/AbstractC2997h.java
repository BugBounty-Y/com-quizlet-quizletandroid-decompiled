package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3536t3;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2997h implements InterfaceC3027n, InterfaceC3007j {
    public final String a;
    public final HashMap b = new HashMap();

    public AbstractC2997h(String str) {
        this.a = str;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final boolean M(String str) {
        return this.b.containsKey(str);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final InterfaceC3027n a(String str) {
        HashMap map = this.b;
        return map.containsKey(str) ? (InterfaceC3027n) map.get(str) : InterfaceC3027n.Q0;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3007j
    public final void b(String str, InterfaceC3027n interfaceC3027n) {
        HashMap map = this.b;
        if (interfaceC3027n == null) {
            map.remove(str);
        } else {
            map.put(str, interfaceC3027n);
        }
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        return "toString".equals(str) ? new C3042q(this.a) : AbstractC3536t3.a(this, new C3042q(str), c1721Kc, arrayList);
    }

    public abstract InterfaceC3027n d(C1721Kc c1721Kc, List list);

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AbstractC2997h)) {
            return false;
        }
        AbstractC2997h abstractC2997h = (AbstractC2997h) obj;
        String str = this.a;
        if (str != null) {
            return str.equals(abstractC2997h.a);
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
        String str = this.a;
        if (str != null) {
            return str.hashCode();
        }
        return 0;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public InterfaceC3027n j() {
        return this;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return new C3002i(this.b.keySet().iterator());
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        return this.a;
    }
}
