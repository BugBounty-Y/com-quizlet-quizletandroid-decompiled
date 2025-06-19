package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.lang.ref.WeakReference;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Ji implements InterfaceC2389n9 {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;

    public /* synthetic */ Ji(InterfaceC2447oi interfaceC2447oi, C2830xf c2830xf, C2584rr c2584rr, C2107gm c2107gm) {
        this.b = interfaceC2447oi;
        this.d = c2830xf;
        this.c = c2584rr;
        this.e = c2107gm;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        switch (this.a) {
            case 0:
                Ki ki = (Ki) ((WeakReference) this.b).get();
                String str = (String) map.get("u");
                if (ki != null && !TextUtils.isEmpty(str)) {
                    ((C2584rr) this.c).a(str, (com.google.android.gms.auth.api.signin.internal.h) this.d, (Tq) this.e, ki.D);
                    break;
                }
                break;
            case 1:
                Object obj2 = ((WeakReference) this.b).get();
                if (obj2 != null) {
                    ((InterfaceC2389n9) this.d).e(obj2, map);
                    break;
                } else {
                    ((C1843ak) this.e).d((String) this.c, this);
                    break;
                }
            default:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
                AbstractC2346m9.b(map, (InterfaceC2447oi) this.b);
                String str2 = (String) map.get("u");
                if (str2 != null) {
                    com.google.common.util.concurrent.e eVarA = AbstractC2346m9.a(interfaceC2529qe, str2);
                    C1721Kc c1721Kc = new C1721Kc(interfaceC2529qe, (C2830xf) this.d, (C2584rr) this.c, (C2107gm) this.e);
                    eVarA.a(new Qv(0, eVarA, c1721Kc), AbstractC2270kd.a);
                    break;
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("URL missing from click GMSG.");
                    break;
                }
        }
    }

    public /* synthetic */ Ji(C1843ak c1843ak, WeakReference weakReference, String str, InterfaceC2389n9 interfaceC2389n9) {
        this.e = c1843ak;
        this.b = weakReference;
        this.c = str;
        this.d = interfaceC2389n9;
    }

    public /* synthetic */ Ji(Ki ki, C2584rr c2584rr, com.google.android.gms.auth.api.signin.internal.h hVar, Tq tq) {
        this.b = new WeakReference(ki);
        this.c = c2584rr;
        this.d = hVar;
        this.e = tq;
    }
}
