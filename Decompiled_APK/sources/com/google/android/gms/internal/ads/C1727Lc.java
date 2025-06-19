package com.google.android.gms.internal.ads;

import android.content.Context;
import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.Lc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1727Lc implements E5 {
    public final Context a;
    public final Object b;
    public final String c;
    public boolean d;

    public C1727Lc(Context context, String str) {
        this.a = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        this.c = str;
        this.d = false;
        this.b = new Object();
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        a(d5.j);
    }

    public final void a(boolean z) {
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        C1739Nc c1739Nc = jVar.y;
        Context context = this.a;
        if (c1739Nc.e(context)) {
            synchronized (this.b) {
                try {
                    if (this.d == z) {
                        return;
                    }
                    this.d = z;
                    String str = this.c;
                    if (TextUtils.isEmpty(str)) {
                        return;
                    }
                    if (this.d) {
                        C1739Nc c1739Nc2 = jVar.y;
                        if (c1739Nc2.e(context)) {
                            c1739Nc2.j(context, str, "beginAdUnitExposure");
                        }
                    } else {
                        C1739Nc c1739Nc3 = jVar.y;
                        if (c1739Nc3.e(context)) {
                            c1739Nc3.j(context, str, "endAdUnitExposure");
                        }
                    }
                } finally {
                }
            }
        }
    }
}
