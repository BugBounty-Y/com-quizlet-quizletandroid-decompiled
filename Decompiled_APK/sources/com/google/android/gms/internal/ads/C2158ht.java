package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/* renamed from: com.google.android.gms.internal.ads.ht, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2158ht {
    public static final Gw c = new Gw("OverlayDisplayService");
    public static final Intent d = new Intent("com.google.android.play.core.lmd.BIND_OVERLAY_DISPLAY_SERVICE").setPackage("com.android.vending");
    public final Tm a;
    public final String b;

    public C2158ht(Context context) {
        if (AbstractC2415nt.a(context)) {
            this.a = new Tm(context.getApplicationContext(), c, d);
        } else {
            this.a = null;
        }
        this.b = context.getPackageName();
    }

    public static void b(String str, Consumer consumer) {
        if ((str == null ? "" : str).trim().isEmpty()) {
            return;
        }
        str.getClass();
        consumer.accept(str.trim());
    }

    public static boolean c(androidx.webkit.internal.p pVar, String str, List list) {
        if (list.stream().anyMatch(new C2070ft())) {
            return true;
        }
        c.a(str, new Object[0]);
        pVar.x(new C1939ct(8160, null));
        return false;
    }

    public final void a(C1982dt c1982dt, androidx.webkit.internal.p pVar, int i) {
        Tm tm = this.a;
        if (tm == null) {
            c.a("error: %s", "Play Store not found.");
        } else {
            if (c(pVar, "Failed to apply OverlayDisplayUpdateRequest: missing appId and sessionToken.", Arrays.asList(c1982dt.a, c1982dt.b))) {
                tm.c(new RunnableC2286kt(tm, new RunnableC1776Td(this, c1982dt, i, pVar), 1));
            }
        }
    }
}
