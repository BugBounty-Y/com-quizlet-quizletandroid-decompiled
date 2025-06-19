package com.google.ads.conversiontracking;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class h {
    public final boolean a;
    public final boolean b;
    public final int c;
    public final long d;
    public final String e;
    public final String f;
    public final String g;
    public long h;

    public h(String str, q qVar, boolean z, boolean z2) {
        this.g = str;
        this.b = z2;
        this.a = z;
        this.h = 0L;
        HashMap map = r.a;
        this.d = System.currentTimeMillis();
        this.c = 0;
        if (z2 || !z) {
            this.f = null;
            this.e = null;
            return;
        }
        int[] iArr = p.a;
        int i = iArr[AbstractC0147y.k(qVar.c)];
        this.f = i != 1 ? i != 2 ? qVar.d : "google_iap_ping:null" : qVar.a;
        int i2 = iArr[AbstractC0147y.k(qVar.c)];
        this.e = i2 != 1 ? i2 != 2 ? "google_nonrepeatable_conversion" : "iap_nonrepeatable_conversion" : "doubleclick_nonrepeatable_conversion";
    }

    public h(long j, String str, String str2, boolean z, boolean z2, String str3, long j2, int i) {
        this.h = j;
        this.g = str;
        this.f = str2;
        this.b = z;
        this.a = z2;
        this.e = str3;
        this.d = j2;
        this.c = i;
    }
}
