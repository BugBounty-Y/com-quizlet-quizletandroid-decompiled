package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.hn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2152hn {
    public final String a;
    public final String b;
    public int c;
    public long d;
    public final Integer e;

    public C2152hn(String str, String str2, int i, long j, Integer num) {
        this.a = str;
        this.b = str2;
        this.c = i;
        this.d = j;
        this.e = num;
    }

    public final String toString() {
        Integer num;
        String strL = this.a + "." + this.c + "." + this.d;
        String str = this.b;
        if (!TextUtils.isEmpty(str)) {
            strL = android.support.v4.media.session.a.l(strL, ".", str);
        }
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F1)).booleanValue() || (num = this.e) == null || TextUtils.isEmpty(str)) {
            return strL;
        }
        return strL + "." + num;
    }
}
