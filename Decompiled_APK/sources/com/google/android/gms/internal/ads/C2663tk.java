package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.ads.mediation.admob.AdMobAdapter;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.tk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2663tk {
    public final C2326lq a;
    public final C2620sk b;

    public C2663tk(C2326lq c2326lq, C2620sk c2620sk) {
        this.a = c2326lq;
        this.b = c2620sk;
    }

    public final InterfaceC1965db a(String str) throws RemoteException {
        InterfaceC2825xa interfaceC2825xa = (InterfaceC2825xa) ((AtomicReference) this.a.d).get();
        if (interfaceC2825xa == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Unexpected call to adapter creator.");
            throw new RemoteException();
        }
        InterfaceC1965db interfaceC1965dbA = interfaceC2825xa.A(str);
        C2620sk c2620sk = this.b;
        synchronized (c2620sk) {
            if (c2620sk.a.containsKey(str)) {
                return interfaceC1965dbA;
            }
            try {
                c2620sk.a.put(str, new C2577rk(str, interfaceC1965dbA.f(), interfaceC1965dbA.h(), true));
                return interfaceC1965dbA;
            } catch (Throwable unused) {
                return interfaceC1965dbA;
            }
        }
    }

    public final C2369mq b(String str, JSONObject jSONObject) {
        InterfaceC2911za interfaceC2911zaC;
        C2620sk c2620sk = this.b;
        try {
            if ("com.google.ads.mediation.admob.AdMobAdapter".equals(str)) {
                interfaceC2911zaC = new BinderC1737Na(new AdMobAdapter());
            } else if ("com.google.ads.mediation.admob.AdMobCustomTabsAdapter".equals(str)) {
                interfaceC2911zaC = new BinderC1737Na(new zzbsd());
            } else {
                InterfaceC2825xa interfaceC2825xa = (InterfaceC2825xa) ((AtomicReference) this.a.d).get();
                if (interfaceC2825xa == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Unexpected call to adapter creator.");
                    throw new RemoteException();
                }
                if ("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter".equals(str) || "com.google.ads.mediation.customevent.CustomEventAdapter".equals(str)) {
                    try {
                        String string = jSONObject.getString("class_name");
                        interfaceC2911zaC = interfaceC2825xa.R(string) ? interfaceC2825xa.C("com.google.android.gms.ads.mediation.customevent.CustomEventAdapter") : interfaceC2825xa.I(string) ? interfaceC2825xa.C(string) : interfaceC2825xa.C("com.google.ads.mediation.customevent.CustomEventAdapter");
                    } catch (JSONException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("Invalid custom event.", e);
                    }
                } else {
                    interfaceC2911zaC = interfaceC2825xa.C(str);
                }
            }
            C2369mq c2369mq = new C2369mq(interfaceC2911zaC);
            c2620sk.b(str, c2369mq);
            return c2369mq;
        } catch (Throwable th) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.r9)).booleanValue()) {
                c2620sk.b(str, null);
            }
            throw new zzfcw(th);
        }
    }
}
