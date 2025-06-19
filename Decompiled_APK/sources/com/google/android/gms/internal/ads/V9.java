package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Looper;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class V9 implements S9, InterfaceC2051fa {
    public final InterfaceC2529qe a;

    public V9(Context context, VersionInfoParcel versionInfoParcel) {
        L9 l9 = com.google.android.gms.ads.internal.j.C.d;
        InterfaceC2529qe interfaceC2529qeG = L9.g(context, null, new com.bumptech.glide.load.engine.cache.f(0, 0, 0), versionInfoParcel, null, new C2429o6(), null, null, null, null, null, null, null, "", false, false);
        this.a = interfaceC2529qeG;
        interfaceC2529qeG.N().setWillNotDraw(true);
    }

    public static final void c(Runnable runnable) {
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        if (Looper.myLooper() == Looper.getMainLooper()) {
            com.google.android.gms.ads.internal.util.A.l("runOnUiThread > the UI thread is the main thread, the runnable will be run now");
            runnable.run();
        } else {
            com.google.android.gms.ads.internal.util.A.l("runOnUiThread > the UI thread is not the main thread, the runnable will be added to the message queue");
            if (com.google.android.gms.ads.internal.util.F.l.post(runnable)) {
                return;
            }
            com.google.android.gms.ads.internal.util.client.i.h("runOnUiThread > the runnable could not be placed to the message queue");
        }
    }

    public final void a() {
        this.a.destroy();
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final /* synthetic */ void b(String str, JSONObject jSONObject) {
        AbstractC1972di.q(this, jSONObject);
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void d(String str, JSONObject jSONObject) {
        zzb(str, jSONObject.toString());
    }

    @Override // com.google.android.gms.internal.ads.R9
    public final void j(String str, Map map) {
        try {
            b("openIntentAsync", C1614q.f.a.i((HashMap) map));
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not convert parameters to JSON.");
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2051fa
    public final void o(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.V(str, new C2881yn(interfaceC2389n9, 6));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2051fa
    public final void q(String str, InterfaceC2389n9 interfaceC2389n9) {
        this.a.O0(str, new U9(this, interfaceC2389n9));
    }

    @Override // com.google.android.gms.internal.ads.S9, com.google.android.gms.internal.ads.W9
    public final void zza(String str) {
        com.google.android.gms.ads.internal.util.A.l("invokeJavascript on adWebView from js");
        c(new T9(this, str, 1));
    }

    @Override // com.google.android.gms.internal.ads.W9
    public final void zzb(String str, String str2) {
        zza(str + "(" + str2 + ");");
    }
}
