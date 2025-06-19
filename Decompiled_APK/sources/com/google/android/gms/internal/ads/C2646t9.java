package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.t9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2646t9 implements com.google.android.gms.ads.internal.overlay.a {
    public boolean a = false;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ InterfaceC1582a c;
    public final /* synthetic */ HashMap d;
    public final /* synthetic */ Map e;

    public C2646t9(boolean z, InterfaceC1582a interfaceC1582a, HashMap map, Map map2) {
        this.b = z;
        this.c = interfaceC1582a;
        this.d = map;
        this.e = map2;
    }

    @Override // com.google.android.gms.ads.internal.overlay.a
    public final void F(int i) {
    }

    @Override // com.google.android.gms.ads.internal.overlay.a
    public final void V(boolean z) {
        if (this.a) {
            return;
        }
        InterfaceC1582a interfaceC1582a = this.c;
        if (z && this.b) {
            ((InterfaceC2447oi) interfaceC1582a).c0();
        }
        this.a = true;
        String str = (String) this.e.get("event_id");
        Boolean boolValueOf = Boolean.valueOf(z);
        HashMap map = this.d;
        map.put(str, boolValueOf);
        ((R9) interfaceC1582a).j("openIntentAsync", map);
    }
}
