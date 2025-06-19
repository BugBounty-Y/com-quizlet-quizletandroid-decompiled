package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.qf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2530qf implements InterfaceC2315lf {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C2530qf(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2315lf
    public final void a(HashMap map) {
        switch (this.a) {
            case 0:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ta)).booleanValue()) {
                    AbstractC2025es.A(Nv.t(((Ts) this.b).l(true)), Throwable.class, new C2487pf(0), AbstractC2270kd.a);
                    return;
                }
                return;
            default:
                String str = (String) map.get("render_in_browser");
                if (TextUtils.isEmpty(str)) {
                    return;
                }
                try {
                    ((Up) this.b).a(Boolean.parseBoolean(str));
                    return;
                } catch (Exception e) {
                    throw new IllegalStateException("Invalid render_in_browser state", e);
                }
        }
    }
}
