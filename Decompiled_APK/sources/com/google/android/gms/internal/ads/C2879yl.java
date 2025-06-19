package com.google.android.gms.internal.ads;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/* renamed from: com.google.android.gms.internal.ads.yl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2879yl implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzbvl b;

    public /* synthetic */ C2879yl(zzbvl zzbvlVar, int i) {
        this.a = i;
        this.b = zzbvlVar;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        InputStream inputStream = (InputStream) obj;
        switch (this.a) {
            case 0:
                return AbstractC2025es.E(new Nl(inputStream, this.b));
            case 1:
                return AbstractC2025es.E(new Nl(inputStream, this.b));
            default:
                String str = new String(Vu.a(inputStream), StandardCharsets.UTF_8);
                zzbvl zzbvlVar = this.b;
                zzbvlVar.j = str;
                return AbstractC2025es.E(zzbvlVar);
        }
    }
}
