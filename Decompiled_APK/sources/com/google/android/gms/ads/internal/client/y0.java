package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

/* loaded from: classes2.dex */
public final class y0 {
    public final String a;
    public final ArrayList b;
    public final Set c;
    public final Bundle d;
    public final String e;
    public final String f;
    public final int g;
    public final Set h;
    public final Bundle i;
    public final Set j;
    public final boolean k;
    public final String l;
    public final int m;
    public long n = 0;

    public y0(x0 x0Var) {
        this.a = x0Var.g;
        this.b = x0Var.h;
        this.c = Collections.unmodifiableSet(x0Var.a);
        this.d = x0Var.b;
        Collections.unmodifiableMap(x0Var.c);
        this.e = x0Var.i;
        this.f = x0Var.j;
        this.g = x0Var.k;
        this.h = Collections.unmodifiableSet(x0Var.d);
        this.i = x0Var.e;
        this.j = Collections.unmodifiableSet(x0Var.f);
        this.k = x0Var.l;
        this.l = x0Var.m;
        this.m = x0Var.n;
    }

    public final boolean a(Context context) {
        com.google.android.gms.ads.p pVar = C0.e().g;
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        String strO = com.google.android.gms.ads.internal.util.client.c.o(context);
        if (this.h.contains(strO)) {
            return true;
        }
        pVar.getClass();
        return new ArrayList(pVar.d).contains(strO);
    }
}
