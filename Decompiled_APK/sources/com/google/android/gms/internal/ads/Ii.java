package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.lang.ref.WeakReference;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Ii implements InterfaceC2389n9 {
    public final /* synthetic */ int a;
    public final WeakReference b;

    public /* synthetic */ Ii(Ki ki, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new WeakReference(ki);
                break;
            default:
                this.b = new WeakReference(ki);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        switch (this.a) {
            case 0:
                Ki ki = (Ki) this.b.get();
                if (ki != null && "_ac".equals((String) map.get("eventName"))) {
                    ki.h.onAdClicked();
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue()) {
                        C2404ni c2404ni = ki.i;
                        c2404ni.c0();
                        if (!TextUtils.isEmpty((CharSequence) map.get("sccg"))) {
                            c2404ni.c();
                            break;
                        }
                    }
                }
                break;
            default:
                Ki ki2 = (Ki) this.b.get();
                if (ki2 != null) {
                    ki2.h.onAdClicked();
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.La)).booleanValue()) {
                        C2404ni c2404ni2 = ki2.i;
                        c2404ni2.c0();
                        if (!TextUtils.isEmpty((CharSequence) map.get("sccg"))) {
                            c2404ni2.c();
                            break;
                        }
                    }
                }
                break;
        }
    }
}
