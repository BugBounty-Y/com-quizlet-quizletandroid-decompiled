package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.na, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2396na implements InterfaceC2356md, Pv {
    public final /* synthetic */ C2313ld a;

    public /* synthetic */ C2396na(C2313ld c2313ld) {
        this.a = c2313ld;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
        C2313ld c2313ld = this.a;
        if (interfaceC2529qe == null) {
            c2313ld.d(new zzegy(1, "Missing webview from video view future."));
        } else {
            interfaceC2529qe.O0("/video", new C1956d9(new E9(c2313ld), 5));
            interfaceC2529qe.e0();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2356md, com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        this.a.d(new zzboc("Cannot get Javascript Engine"));
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        com.google.android.gms.ads.internal.util.client.i.e("Failed to load media data due to video view load failure.");
        this.a.d(th);
    }
}
