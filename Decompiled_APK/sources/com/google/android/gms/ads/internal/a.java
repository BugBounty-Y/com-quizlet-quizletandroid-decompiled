package com.google.android.gms.ads.internal;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.ads.internal.util.t;
import com.google.android.gms.internal.ads.C1673Cc;
import com.google.android.gms.internal.ads.InterfaceC1679Dc;
import com.google.android.gms.internal.ads.zzbut;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;
    public boolean b;
    public final InterfaceC1679Dc c;
    public final zzbut d = new zzbut(false, Collections.EMPTY_LIST);

    public a(Context context, InterfaceC1679Dc interfaceC1679Dc) {
        this.a = context;
        this.c = interfaceC1679Dc;
    }

    public final void a(String str) {
        List<String> list;
        zzbut zzbutVar = this.d;
        InterfaceC1679Dc interfaceC1679Dc = this.c;
        if ((interfaceC1679Dc == null || !((C1673Cc) interfaceC1679Dc).g.f) && !zzbutVar.a) {
            return;
        }
        if (str == null) {
            str = "";
        }
        if (interfaceC1679Dc != null) {
            ((C1673Cc) interfaceC1679Dc).a(str, null, 3);
            return;
        }
        if (!zzbutVar.a || (list = zzbutVar.b) == null) {
            return;
        }
        for (String str2 : list) {
            if (!TextUtils.isEmpty(str2)) {
                String strReplace = str2.replace("{NAVIGATION_URL}", Uri.encode(str));
                F f = j.C.c;
                new t(this.a, "", strReplace, null).R();
            }
        }
    }

    public final boolean b() {
        InterfaceC1679Dc interfaceC1679Dc = this.c;
        return ((interfaceC1679Dc == null || !((C1673Cc) interfaceC1679Dc).g.f) && !this.d.a) || this.b;
    }
}
