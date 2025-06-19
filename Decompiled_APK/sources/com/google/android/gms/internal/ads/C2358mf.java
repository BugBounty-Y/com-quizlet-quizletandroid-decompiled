package com.google.android.gms.internal.ads;

import android.content.SharedPreferences;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.mf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2358mf implements InterfaceC2315lf {
    public final /* synthetic */ int a;
    public final com.google.android.gms.ads.internal.util.C b;

    public /* synthetic */ C2358mf(com.google.android.gms.ads.internal.util.C c, int i) {
        this.a = i;
        this.b = c;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2315lf
    public final void a(HashMap map) {
        switch (this.a) {
            case 0:
                boolean z = Boolean.parseBoolean((String) map.get("content_url_opted_out"));
                com.google.android.gms.ads.internal.util.C c = this.b;
                c.l();
                synchronized (c.a) {
                    try {
                        if (c.u == z) {
                            return;
                        }
                        c.u = z;
                        SharedPreferences.Editor editor = c.g;
                        if (editor != null) {
                            editor.putBoolean("content_url_opted_out", z);
                            c.g.apply();
                        }
                        c.m();
                        return;
                    } finally {
                    }
                }
            default:
                boolean z2 = Boolean.parseBoolean((String) map.get("content_vertical_opted_out"));
                com.google.android.gms.ads.internal.util.C c2 = this.b;
                c2.l();
                synchronized (c2.a) {
                    try {
                        if (c2.v == z2) {
                            return;
                        }
                        c2.v = z2;
                        SharedPreferences.Editor editor2 = c2.g;
                        if (editor2 != null) {
                            editor2.putBoolean("content_vertical_opted_out", z2);
                            c2.g.apply();
                        }
                        c2.m();
                        return;
                    } finally {
                    }
                }
        }
    }
}
