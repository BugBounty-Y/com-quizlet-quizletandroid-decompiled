package com.google.android.gms.internal.ads;

import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.If, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1712If implements Runnable {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ InterfaceC2529qe b;
    public final /* synthetic */ JSONObject c;

    public /* synthetic */ RunnableC1712If(InterfaceC2529qe interfaceC2529qe, JSONObject jSONObject) {
        this.b = interfaceC2529qe;
        this.c = jSONObject;
    }

    @Override // java.lang.Runnable
    public final void run() {
        InterfaceC2529qe interfaceC2529qe = this.b;
        JSONObject jSONObject = this.c;
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.util.client.i.d("Calling AFMA_updateActiveView(" + jSONObject.toString() + ")");
                interfaceC2529qe.d("AFMA_updateActiveView", jSONObject);
                break;
            default:
                Bu bu = Ui.H;
                interfaceC2529qe.b("onVideoEvent", jSONObject);
                break;
        }
    }

    public /* synthetic */ RunnableC1712If(JSONObject jSONObject, InterfaceC2529qe interfaceC2529qe) {
        this.c = jSONObject;
        this.b = interfaceC2529qe;
    }
}
