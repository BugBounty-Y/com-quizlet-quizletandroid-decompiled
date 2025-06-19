package com.google.android.gms.internal.ads;

import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.Ma, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1731Ma implements com.google.android.gms.ads.mediation.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC1671Ca b;
    public final /* synthetic */ BinderC1737Na c;

    public /* synthetic */ C1731Ma(BinderC1737Na binderC1737Na, InterfaceC1671Ca interfaceC1671Ca, int i) {
        this.a = i;
        this.b = interfaceC1671Ca;
        this.c = binderC1737Na;
    }

    @Override // com.google.android.gms.ads.mediation.c
    public final void s(com.google.android.gms.ads.b bVar) {
        switch (this.a) {
            case 0:
                try {
                    String canonicalName = this.c.a.getClass().getCanonicalName();
                    int i = bVar.a;
                    String str = bVar.b;
                    com.google.android.gms.ads.internal.util.client.i.d(canonicalName + "failed to loaded mediation ad: ErrorCode = " + i + ". ErrorMessage = " + str + ". ErrorDomain = " + bVar.c);
                    InterfaceC1671Ca interfaceC1671Ca = this.b;
                    interfaceC1671Ca.S0(bVar.a());
                    interfaceC1671Ca.I0(i, str);
                    interfaceC1671Ca.e(i);
                    break;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                }
            case 1:
                try {
                    String canonicalName2 = this.c.a.getClass().getCanonicalName();
                    int i2 = bVar.a;
                    String str2 = bVar.b;
                    com.google.android.gms.ads.internal.util.client.i.d(canonicalName2 + "failed to load mediation ad: ErrorCode = " + i2 + ". ErrorMessage = " + str2 + ". ErrorDomain = " + bVar.c);
                    InterfaceC1671Ca interfaceC1671Ca2 = this.b;
                    interfaceC1671Ca2.S0(bVar.a());
                    interfaceC1671Ca2.I0(i2, str2);
                    interfaceC1671Ca2.e(i2);
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    return;
                }
            default:
                try {
                    String canonicalName3 = this.c.a.getClass().getCanonicalName();
                    int i3 = bVar.a;
                    String str3 = bVar.b;
                    com.google.android.gms.ads.internal.util.client.i.d(canonicalName3 + "failed to load mediation ad: ErrorCode = " + i3 + ". ErrorMessage = " + str3 + ". ErrorDomain = " + bVar.c);
                    InterfaceC1671Ca interfaceC1671Ca3 = this.b;
                    interfaceC1671Ca3.S0(bVar.a());
                    interfaceC1671Ca3.I0(i3, str3);
                    interfaceC1671Ca3.e(i3);
                    break;
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e3);
                    return;
                }
        }
    }
}
