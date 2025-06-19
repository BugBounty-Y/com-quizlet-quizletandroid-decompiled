package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.view.View;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.Td, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC1776Td implements Runnable {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public RunnableC1776Td(AbstractC1794Wd abstractC1794Wd, String str, String str2, int i) {
        this.c = str;
        this.d = str2;
        this.b = i;
        this.e = abstractC1794Wd;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                HashMap map = new HashMap();
                map.put("event", "precacheComplete");
                map.put("src", (String) this.c);
                map.put("cachedSrc", (String) this.d);
                map.put("totalBytes", Integer.toString(this.b));
                AbstractC1794Wd.k((AbstractC1794Wd) this.e, map);
                return;
            case 1:
                ((C1669Be) this.c).A((View) this.d, (InterfaceC1679Dc) this.e, this.b - 1);
                return;
            default:
                C2158ht c2158ht = (C2158ht) this.c;
                C1982dt c1982dt = (C1982dt) this.d;
                int i = this.b;
                androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) this.e;
                try {
                    Tm tm = c2158ht.a;
                    if (tm == null) {
                        throw null;
                    }
                    Ys ys = (Ys) tm.j;
                    if (ys == null) {
                        return;
                    }
                    String str = c2158ht.b;
                    Bundle bundle = new Bundle();
                    bundle.putString("callerPackage", str);
                    bundle.putInt("displayMode", i);
                    C2158ht.b(c1982dt.a, new C2026et(bundle, 0));
                    C2158ht.b(c1982dt.b, new C2026et(bundle, 5));
                    BinderC2114gt binderC2114gt = new BinderC2114gt(c2158ht, pVar);
                    Ws ws = (Ws) ys;
                    Parcel parcelF3 = ws.f3();
                    AbstractC2857y5.c(parcelF3, bundle);
                    AbstractC2857y5.e(parcelF3, binderC2114gt);
                    ws.e4(3, parcelF3);
                    return;
                } catch (RemoteException e) {
                    C2158ht.c.b(e, "switchDisplayMode overlay display to %d from: %s", Integer.valueOf(i), c2158ht.b);
                    return;
                }
        }
    }

    public /* synthetic */ RunnableC1776Td(C1669Be c1669Be, View view, InterfaceC1679Dc interfaceC1679Dc, int i) {
        this.c = c1669Be;
        this.d = view;
        this.e = interfaceC1679Dc;
        this.b = i;
    }

    public /* synthetic */ RunnableC1776Td(C2158ht c2158ht, C1982dt c1982dt, int i, androidx.webkit.internal.p pVar) {
        this.c = c2158ht;
        this.d = c1982dt;
        this.b = i;
        this.e = pVar;
    }
}
