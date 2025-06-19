package com.google.android.gms.ads.nonagon.signalgeneration;

import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.JsonReader;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.Fv;
import com.google.android.gms.internal.ads.InterfaceC2544qt;
import com.google.android.gms.internal.ads.Nl;
import com.google.android.gms.internal.ads.zzbvl;
import java.io.InputStreamReader;
import java.util.ArrayList;
import org.json.JSONException;

/* renamed from: com.google.android.gms.ads.nonagon.signalgeneration.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C1638d implements Fv {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C1638d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) {
        switch (this.a) {
            case 0:
                final Uri uri = (Uri) obj;
                final i iVar = (i) this.b;
                return AbstractC2025es.L(iVar.f4("google.afma.nativeAds.getPublisherCustomRenderedClickSignals"), new InterfaceC2544qt(iVar, uri) { // from class: com.google.android.gms.ads.nonagon.signalgeneration.e
                    public final /* synthetic */ Uri a;

                    {
                        this.a = uri;
                    }

                    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
                    public final Object apply(Object obj2) {
                        String str = (String) obj2;
                        boolean zIsEmpty = TextUtils.isEmpty(str);
                        Uri uri2 = this.a;
                        return !zIsEmpty ? i.m4(uri2, "nas", str) : uri2;
                    }
                }, iVar.g);
            case 1:
                final ArrayList arrayList = (ArrayList) obj;
                final i iVar2 = (i) this.b;
                return AbstractC2025es.L(iVar2.f4("google.afma.nativeAds.getPublisherCustomRenderedImpressionSignals"), new InterfaceC2544qt() { // from class: com.google.android.gms.ads.nonagon.signalgeneration.b
                    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
                    public final Object apply(Object obj2) {
                        String str = (String) obj2;
                        ArrayList arrayList2 = new ArrayList();
                        for (Uri uri2 : arrayList) {
                            i iVar3 = iVar2;
                            if (!i.k4(uri2, iVar3.z, iVar3.A) || TextUtils.isEmpty(str)) {
                                arrayList2.add(uri2);
                            } else {
                                arrayList2.add(i.m4(uri2, "nas", str));
                            }
                        }
                        return arrayList2;
                    }
                }, iVar2.g);
            default:
                Nl nl = (Nl) obj;
                q qVar = new q(new JsonReader(new InputStreamReader(nl.a)), nl.b);
                zzbvl zzbvlVar = (zzbvl) this.b;
                try {
                    qVar.b = C1614q.f.a.h(zzbvlVar.a).toString();
                } catch (JSONException unused) {
                    qVar.b = "{}";
                }
                Bundle bundle = zzbvlVar.n;
                if (!bundle.isEmpty()) {
                    try {
                        qVar.c = C1614q.f.a.h(bundle).toString();
                    } catch (JSONException unused2) {
                    }
                }
                return AbstractC2025es.E(qVar);
        }
    }
}
