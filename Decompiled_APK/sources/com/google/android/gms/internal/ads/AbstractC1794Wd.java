package com.google.android.gms.internal.ads;

import android.content.Context;
import java.lang.ref.WeakReference;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.Wd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1794Wd {
    public final Context a;
    public final String b;
    public final WeakReference c;

    public AbstractC1794Wd(InterfaceC2529qe interfaceC2529qe) {
        Context context = interfaceC2529qe.getContext();
        this.a = context;
        this.b = com.google.android.gms.ads.internal.j.C.c.y(context, interfaceC2529qe.l().a);
        this.c = new WeakReference(interfaceC2529qe);
    }

    public static /* bridge */ /* synthetic */ void k(AbstractC1794Wd abstractC1794Wd, HashMap map) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) abstractC1794Wd.c.get();
        if (interfaceC2529qe != null) {
            interfaceC2529qe.j("onPrecacheEvent", map);
        }
    }

    public void j() {
    }

    public abstract void l();

    public final void m(String str, String str2, String str3, String str4) {
        com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1788Vd((Object) this, str, str2, (Object) str3, (Object) str4, 0));
    }

    public void n(int i) {
    }

    public void o(int i) {
    }

    public void p(int i) {
    }

    public void q(int i) {
    }

    public abstract boolean r(String str);

    public boolean s(String str, String[] strArr) {
        return r(str);
    }

    public boolean t(String str, String[] strArr, C1746Od c1746Od) {
        return r(str);
    }
}
