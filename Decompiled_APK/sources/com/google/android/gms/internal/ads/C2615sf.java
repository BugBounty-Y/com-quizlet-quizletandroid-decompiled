package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.sf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2615sf implements InterfaceC2315lf {
    @Override // com.google.android.gms.internal.ads.InterfaceC2315lf
    public final void a(HashMap map) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ta)).booleanValue() || map.isEmpty()) {
            return;
        }
        String str = (String) map.get("is_topics_ad_personalization_allowed");
        if (TextUtils.isEmpty(str)) {
            return;
        }
        com.google.android.gms.ads.internal.j.C.h.d().d(Boolean.parseBoolean(str));
    }
}
