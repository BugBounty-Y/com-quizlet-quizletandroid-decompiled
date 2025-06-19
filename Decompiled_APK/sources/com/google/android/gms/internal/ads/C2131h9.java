package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.h9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2131h9 implements InterfaceC2544qt {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ C2131h9(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
    public final Object apply(Object obj) {
        String strReplace = this.b;
        switch (this.a) {
            case 0:
                String str = (String) obj;
                C2175i9 c2175i9 = AbstractC2346m9.a;
                if (str == null) {
                    return strReplace;
                }
                if (((Boolean) V7.f.o()).booleanValue()) {
                    String[] strArr = {".doubleclick.net", ".googleadservices.com", ".googlesyndication.com"};
                    String host = Uri.parse(strReplace).getHost();
                    for (int i = 0; i < 3; i++) {
                        if (!host.endsWith(strArr[i])) {
                        }
                    }
                    return strReplace;
                }
                String str2 = (String) V7.a.o();
                String str3 = (String) V7.b.o();
                if (!TextUtils.isEmpty(str2)) {
                    strReplace = strReplace.replace(str2, str);
                }
                if (TextUtils.isEmpty(str3)) {
                    return strReplace;
                }
                Uri uri = Uri.parse(strReplace);
                return TextUtils.isEmpty(uri.getQueryParameter(str3)) ? uri.buildUpon().appendQueryParameter(str3, str).toString() : strReplace;
            case 1:
                Throwable th = (Throwable) obj;
                C2175i9 c2175i92 = AbstractC2346m9.a;
                if (((Boolean) V7.i.o()).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.h("prepareClickUrl.attestation2", th);
                }
                return strReplace;
            case 2:
                return new Jj(strReplace, (BinderC2474p8) obj);
            default:
                Throwable th2 = (Throwable) obj;
                C2925zo c2925zo = Qo.k;
                com.google.android.gms.ads.internal.util.client.i.e("Error calling adapter: ".concat(String.valueOf(strReplace)));
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Wc)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.g("rtbSignal.fetchRtbJsonInfo-".concat(String.valueOf(strReplace)), th2);
                    return null;
                }
                com.google.android.gms.ads.internal.j.C.h.h("rtbSignal.fetchRtbJsonInfo-".concat(String.valueOf(strReplace)), th2);
                return null;
        }
    }
}
