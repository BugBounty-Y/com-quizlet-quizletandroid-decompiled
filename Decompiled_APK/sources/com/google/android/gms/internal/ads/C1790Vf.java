package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Vf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1790Vf implements InterfaceC2617sh {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;
    public final /* synthetic */ VersionInfoParcel c;
    public final /* synthetic */ Vp d;
    public final /* synthetic */ C2023eq e;

    public /* synthetic */ C1790Vf(Context context, VersionInfoParcel versionInfoParcel, Vp vp, C2023eq c2023eq, int i) {
        this.a = i;
        this.b = context;
        this.c = versionInfoParcel;
        this.d = vp;
        this.e = c2023eq;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        switch (this.a) {
            case 0:
                androidx.camera.camera2.interop.c cVar = com.google.android.gms.ads.internal.j.C.o;
                JSONObject jSONObject = this.d.C;
                cVar.i(this.b, this.c.a, jSONObject.toString(), this.e.f);
                break;
            default:
                androidx.camera.camera2.interop.c cVar2 = com.google.android.gms.ads.internal.j.C.o;
                JSONObject jSONObject2 = this.d.C;
                cVar2.i(this.b, this.c.a, jSONObject2.toString(), this.e.f);
                break;
        }
    }
}
