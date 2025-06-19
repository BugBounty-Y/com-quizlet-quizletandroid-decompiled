package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.ads.zl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2922zl implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzbvl b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    public /* synthetic */ C2922zl(Object obj, zzbvl zzbvlVar, int i, int i2) {
        this.a = i2;
        this.d = obj;
        this.b = zzbvlVar;
        this.c = i;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        Bundle bundle;
        Bundle bundle2;
        switch (this.a) {
            case 0:
                zzbvl zzbvlVar = this.b;
                if (zzbvlVar != null && (bundle = zzbvlVar.m) != null) {
                    bundle.putBoolean("ls", true);
                }
                com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) this.d;
                return AbstractC2025es.N(((Tl) ((InterfaceC2907zC) aVar.d).zzb()).f4(zzbvlVar, this.c), new C2879yl(zzbvlVar, 0), (C2227jd) aVar.b);
            default:
                zzbvl zzbvlVar2 = this.b;
                if (zzbvlVar2 != null && (bundle2 = zzbvlVar2.m) != null) {
                    bundle2.putBoolean("ls", true);
                }
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar = (com.quizlet.data.repository.folderwithcreatorinclass.e) this.d;
                return AbstractC2025es.N(((Tl) ((InterfaceC2907zC) eVar.e).zzb()).g4(zzbvlVar2, this.c), new C2879yl(zzbvlVar2, 1), (C2227jd) eVar.b);
        }
    }
}
