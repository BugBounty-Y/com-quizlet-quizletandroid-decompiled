package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.y9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2861y9 implements InterfaceC2389n9 {
    public final Context a;

    public C2861y9(Context context) {
        this.a = context;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        if (!map.containsKey("text") || TextUtils.isEmpty((CharSequence) map.get("text"))) {
            return;
        }
        com.google.android.gms.ads.internal.util.A.l("Opening Share Sheet with text: ".concat(String.valueOf((String) map.get("text"))));
        Intent intent = new Intent();
        intent.setAction("android.intent.action.SEND");
        intent.setType("text/plain");
        intent.putExtra("android.intent.extra.TEXT", (String) map.get("text"));
        if (map.containsKey("title")) {
            intent.putExtra("android.intent.extra.TITLE", (String) map.get("title"));
        }
        try {
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            com.google.android.gms.ads.internal.util.F.q(this.a, intent);
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to open Share Sheet", e);
            com.google.android.gms.ads.internal.j.C.h.h("ShareSheetGmsgHandler.onGmsg", e);
        }
    }
}
