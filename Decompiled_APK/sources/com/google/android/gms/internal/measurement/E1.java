package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3560x3;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/* loaded from: classes2.dex */
public final class E1 extends AbstractC2997h {
    public final /* synthetic */ int c = 1;
    public final Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E1(androidx.compose.foundation.text.input.internal.u uVar) {
        super("getValue");
        this.d = uVar;
    }

    @Override // com.google.android.gms.internal.measurement.AbstractC2997h
    public final InterfaceC3027n d(C1721Kc c1721Kc, List list) {
        TreeMap treeMap;
        switch (this.c) {
            case 0:
                AbstractC3554w3.g(this.a, list, 3);
                String strZzi = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(0)).zzi();
                InterfaceC3027n interfaceC3027n = (InterfaceC3027n) list.get(1);
                C3056t c3056t = (C3056t) c1721Kc.c;
                long jA = (long) AbstractC3554w3.a(c3056t.a(c1721Kc, interfaceC3027n).g().doubleValue());
                InterfaceC3027n interfaceC3027nA = c3056t.a(c1721Kc, (InterfaceC3027n) list.get(2));
                HashMap mapF = interfaceC3027nA instanceof C3012k ? AbstractC3554w3.f((C3012k) interfaceC3027nA) : new HashMap();
                com.quizlet.data.repository.user.a aVar = (com.quizlet.data.repository.user.a) this.d;
                aVar.getClass();
                HashMap map = new HashMap();
                for (String str : mapF.keySet()) {
                    HashMap map2 = ((C2967b) aVar.b).c;
                    map.put(str, C2967b.b(str, map2.containsKey(str) ? map2.get(str) : null, mapF.get(str)));
                }
                ((ArrayList) aVar.d).add(new C2967b(strZzi, jA, map));
                return InterfaceC3027n.Q0;
            case 1:
                AbstractC3554w3.g("getValue", list, 2);
                InterfaceC3027n interfaceC3027nA2 = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(0));
                InterfaceC3027n interfaceC3027nA3 = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(1));
                String strZzi2 = interfaceC3027nA2.zzi();
                androidx.compose.foundation.text.input.internal.u uVar = (androidx.compose.foundation.text.input.internal.u) this.d;
                Map map3 = (Map) ((com.google.android.gms.measurement.internal.T) uVar.c).e.get((String) uVar.b);
                String str2 = (map3 == null || !map3.containsKey(strZzi2)) ? null : (String) map3.get(strZzi2);
                return str2 != null ? new C3042q(str2) : interfaceC3027nA3;
            case 2:
                return InterfaceC3027n.Q0;
            case 3:
                try {
                    return AbstractC3560x3.b(((com.google.android.gms.measurement.internal.Q) this.d).call());
                } catch (Exception unused) {
                    return InterfaceC3027n.Q0;
                }
            default:
                AbstractC3554w3.g(this.a, list, 3);
                ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) list.get(0)).zzi();
                InterfaceC3027n interfaceC3027n2 = (InterfaceC3027n) list.get(1);
                C3056t c3056t2 = (C3056t) c1721Kc.c;
                InterfaceC3027n interfaceC3027nA4 = c3056t2.a(c1721Kc, interfaceC3027n2);
                if (!(interfaceC3027nA4 instanceof C3022m)) {
                    throw new IllegalArgumentException("Invalid callback type");
                }
                InterfaceC3027n interfaceC3027nA5 = c3056t2.a(c1721Kc, (InterfaceC3027n) list.get(2));
                if (!(interfaceC3027nA5 instanceof C3012k)) {
                    throw new IllegalArgumentException("Invalid callback params");
                }
                C3012k c3012k = (C3012k) interfaceC3027nA5;
                if (!c3012k.a.containsKey(DBUserFields.Names.USER_UPGRADE_TYPE)) {
                    throw new IllegalArgumentException("Undefined rule type");
                }
                String strZzi3 = c3012k.a(DBUserFields.Names.USER_UPGRADE_TYPE).zzi();
                int iB = c3012k.a.containsKey("priority") ? AbstractC3554w3.b(c3012k.a("priority").g().doubleValue()) : 1000;
                C3022m c3022m = (C3022m) interfaceC3027nA4;
                C3056t c3056t3 = (C3056t) this.d;
                c3056t3.getClass();
                if ("create".equals(strZzi3)) {
                    treeMap = (TreeMap) c3056t3.b;
                } else {
                    if (!"edit".equals(strZzi3)) {
                        throw new IllegalStateException("Unknown callback type: ".concat(String.valueOf(strZzi3)));
                    }
                    treeMap = (TreeMap) c3056t3.a;
                }
                if (treeMap.containsKey(Integer.valueOf(iB))) {
                    iB = ((Integer) treeMap.lastKey()).intValue() + 1;
                }
                treeMap.put(Integer.valueOf(iB), c3022m);
                return InterfaceC3027n.Q0;
        }
    }

    public E1(com.google.android.gms.internal.instantapps.a aVar) {
        super("internal.logger");
        this.d = aVar;
        this.b.put("log", new i4(this, false, true));
        this.b.put("silent", new C3010j2("silent", 1));
        ((AbstractC2997h) this.b.get("silent")).b("log", new i4(this, true, true));
        this.b.put("unmonitored", new C3010j2("unmonitored", 2));
        ((AbstractC2997h) this.b.get("unmonitored")).b("log", new i4(this, false, false));
    }

    public E1(C3056t c3056t) {
        super("internal.registerCallback");
        this.d = c3056t;
    }

    public E1(com.google.android.gms.measurement.internal.Q q) {
        super("internal.appMetadata");
        this.d = q;
    }

    public E1(com.quizlet.data.repository.user.a aVar) {
        super("internal.eventLogger");
        this.d = aVar;
    }
}
