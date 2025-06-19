package com.facebook.appevents.aam;

import android.app.Activity;
import android.view.View;
import android.view.ViewTreeObserver;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();
    public static boolean b;

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0043  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.util.HashMap r3, java.lang.String r4, java.lang.String r5) {
        /*
            java.util.HashMap r0 = com.facebook.appevents.aam.d.e
            int r0 = r4.hashCode()
            r1 = 0
            switch(r0) {
                case 3585: goto L51;
                case 3586: goto L3a;
                case 3587: goto L31;
                case 3588: goto Lc;
                default: goto La;
            }
        La:
            goto L77
        Lc:
            java.lang.String r0 = "r6"
            boolean r0 = r4.equals(r0)
            if (r0 != 0) goto L15
            goto L77
        L15:
            java.lang.String r0 = "-"
            boolean r2 = kotlin.text.StringsKt.G(r5, r0, r1)
            if (r2 == 0) goto L77
            kotlin.text.Regex r2 = new kotlin.text.Regex
            r2.<init>(r0)
            java.util.List r5 = r2.g(r1, r5)
            java.lang.String[] r0 = new java.lang.String[r1]
            java.lang.Object[] r5 = r5.toArray(r0)
            java.lang.String[] r5 = (java.lang.String[]) r5
            r5 = r5[r1]
            goto L77
        L31:
            java.lang.String r0 = "r5"
            boolean r0 = r4.equals(r0)
            if (r0 != 0) goto L43
            goto L77
        L3a:
            java.lang.String r0 = "r4"
            boolean r0 = r4.equals(r0)
            if (r0 != 0) goto L43
            goto L77
        L43:
            kotlin.text.Regex r0 = new kotlin.text.Regex
            java.lang.String r1 = "[^a-z]+"
            r0.<init>(r1)
            java.lang.String r1 = ""
            java.lang.String r5 = r0.replace(r5, r1)
            goto L77
        L51:
            java.lang.String r0 = "r3"
            boolean r0 = r4.equals(r0)
            if (r0 != 0) goto L5a
            goto L77
        L5a:
            java.lang.String r0 = "m"
            boolean r2 = kotlin.text.D.r(r5, r0, r1)
            if (r2 != 0) goto L76
            java.lang.String r2 = "b"
            boolean r2 = kotlin.text.D.r(r5, r2, r1)
            if (r2 != 0) goto L76
            java.lang.String r2 = "ge"
            boolean r5 = kotlin.text.D.r(r5, r2, r1)
            if (r5 == 0) goto L73
            goto L76
        L73:
            java.lang.String r5 = "f"
            goto L77
        L76:
            r5 = r0
        L77:
            r3.put(r4, r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.aam.a.a(java.util.HashMap, java.lang.String, java.lang.String):void");
    }

    public static void b(Activity activity) {
        View viewC;
        Intrinsics.checkNotNullParameter(activity, "activity");
        int iHashCode = activity.hashCode();
        HashMap map = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            try {
                map = d.e;
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(d.class, th);
            }
        }
        Integer numValueOf = Integer.valueOf(iHashCode);
        Object dVar = map.get(numValueOf);
        if (dVar == null) {
            dVar = new d(activity);
            map.put(numValueOf, dVar);
        }
        d dVar2 = (d) dVar;
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            return;
        }
        try {
            if (com.facebook.internal.instrument.crashshield.a.b(dVar2)) {
                return;
            }
            try {
                if (!dVar2.d.getAndSet(true) && (viewC = com.facebook.appevents.internal.d.c((Activity) dVar2.c.get())) != null) {
                    ViewTreeObserver viewTreeObserver = viewC.getViewTreeObserver();
                    if (viewTreeObserver.isAlive()) {
                        viewTreeObserver.addOnGlobalFocusChangeListener(dVar2);
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(dVar2, th2);
            }
        } catch (Throwable th3) {
            com.facebook.internal.instrument.crashshield.a.a(d.class, th3);
        }
    }
}
