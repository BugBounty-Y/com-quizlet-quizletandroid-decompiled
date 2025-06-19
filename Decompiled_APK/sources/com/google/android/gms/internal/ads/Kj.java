package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zzfw;

/* loaded from: classes2.dex */
public final /* synthetic */ class Kj implements InterfaceC1681De {
    public final /* synthetic */ int a;
    public final /* synthetic */ Oj b;
    public final /* synthetic */ InterfaceC2529qe c;
    public final /* synthetic */ C2257k6 d;

    public /* synthetic */ Kj(Oj oj, InterfaceC2529qe interfaceC2529qe, C2257k6 c2257k6, int i) {
        this.a = i;
        this.b = oj;
        this.c = interfaceC2529qe;
        this.d = c2257k6;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public final void A(String str, int i, String str2, boolean z) {
        switch (this.a) {
            case 0:
                C2257k6 c2257k6 = this.d;
                if (!z) {
                    c2257k6.d(new zzegy(1, "Html video Web View failed to load. Error code: " + i + ", Description: " + str + ", Failing URL: " + str2));
                    break;
                } else {
                    zzfw zzfwVar = this.b.a.a;
                    if (zzfwVar != null) {
                        InterfaceC2529qe interfaceC2529qe = this.c;
                        if (interfaceC2529qe.p() != null) {
                            interfaceC2529qe.p().g4(zzfwVar);
                        }
                    }
                    c2257k6.e();
                    break;
                }
            default:
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.a4)).booleanValue();
                C2257k6 c2257k62 = this.d;
                Oj oj = this.b;
                InterfaceC2529qe interfaceC2529qe2 = this.c;
                if (!zBooleanValue) {
                    zzfw zzfwVar2 = oj.a.a;
                    if (zzfwVar2 != null && interfaceC2529qe2.p() != null) {
                        interfaceC2529qe2.p().g4(zzfwVar2);
                    }
                    c2257k62.e();
                    break;
                } else if (!z) {
                    c2257k62.d(new zzegy(1, "Native Video WebView failed to load. Error code: " + i + ", Description: " + str + ", Failing URL: " + str2));
                    break;
                } else {
                    zzfw zzfwVar3 = oj.a.a;
                    if (zzfwVar3 != null && interfaceC2529qe2.p() != null) {
                        interfaceC2529qe2.p().g4(zzfwVar3);
                    }
                    c2257k62.e();
                    break;
                }
                break;
        }
    }
}
