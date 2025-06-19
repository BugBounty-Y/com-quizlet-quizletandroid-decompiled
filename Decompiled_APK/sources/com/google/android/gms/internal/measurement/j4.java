package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final class j4 extends AbstractC2997h {
    public final C3005i2 c;
    public final HashMap d;

    public j4(C3005i2 c3005i2) {
        super("require");
        this.d = new HashMap();
        this.c = c3005i2;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractC2997h
    public final InterfaceC3027n d(C1721Kc c1721Kc, List list) {
        InterfaceC3027n interfaceC3027n;
        AbstractC3554w3.g("require", list, 1);
        String strZzi = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(0)).zzi();
        HashMap map = this.d;
        if (map.containsKey(strZzi)) {
            return (InterfaceC3027n) map.get(strZzi);
        }
        HashMap map2 = (HashMap) this.c.a;
        if (map2.containsKey(strZzi)) {
            try {
                interfaceC3027n = (InterfaceC3027n) ((Callable) map2.get(strZzi)).call();
            } catch (Exception unused) {
                throw new IllegalStateException("Failed to create API implementation: ".concat(String.valueOf(strZzi)));
            }
        } else {
            interfaceC3027n = InterfaceC3027n.Q0;
        }
        if (interfaceC3027n instanceof AbstractC2997h) {
            map.put(strZzi, (AbstractC2997h) interfaceC3027n);
        }
        return interfaceC3027n;
    }
}
