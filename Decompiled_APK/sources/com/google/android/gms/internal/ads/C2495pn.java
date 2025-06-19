package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.pn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2495pn implements InterfaceC2837xm {
    public final /* synthetic */ int a;
    public final C2663tk b;
    public final Object c;

    public C2495pn(An an, C2663tk c2663tk) {
        this.a = 1;
        this.c = an;
        this.b = c2663tk;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2837xm
    public final C2880ym a(String str, JSONObject jSONObject) {
        C2880ym c2880ym;
        InterfaceC1965db interfaceC1965dbA;
        switch (this.a) {
            case 0:
                synchronized (this) {
                    try {
                        HashMap map = (HashMap) this.c;
                        c2880ym = (C2880ym) map.get(str);
                        if (c2880ym == null) {
                            c2880ym = new C2880ym(this.b.b(str, jSONObject), new Sm(), str);
                            map.put(str, c2880ym);
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return c2880ym;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H1)).booleanValue()) {
                    try {
                        interfaceC1965dbA = this.b.a(str);
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("Coundn't create RTB adapter: ", e);
                    }
                } else {
                    ConcurrentHashMap concurrentHashMap = ((An) this.c).a;
                    interfaceC1965dbA = concurrentHashMap.containsKey(str) ? (InterfaceC1965db) concurrentHashMap.get(str) : null;
                }
                if (interfaceC1965dbA == null) {
                    return null;
                }
                return new C2880ym(interfaceC1965dbA, new Rm(), str);
        }
    }

    public C2495pn(C2663tk c2663tk) {
        this.a = 0;
        this.c = new HashMap();
        this.b = c2663tk;
    }
}
