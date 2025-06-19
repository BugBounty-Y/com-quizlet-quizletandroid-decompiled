package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.os.SystemClock;
import android.view.View;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.u9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2689u9 implements InterfaceC2389n9 {
    public final com.google.android.gms.ads.internal.a a;
    public final Hk b;
    public final C2397nb d;
    public final C2107gm e;
    public final C2830xf f;
    public com.google.android.gms.ads.internal.overlay.a g = null;
    public final C2227jd h = AbstractC2270kd.g;
    public final com.google.android.gms.ads.internal.util.client.k c = new com.google.android.gms.ads.internal.util.client.k(null);

    public C2689u9(com.google.android.gms.ads.internal.a aVar, C2397nb c2397nb, C2107gm c2107gm, Hk hk, C2830xf c2830xf) {
        this.a = aVar;
        this.d = c2397nb;
        this.e = c2107gm;
        this.b = hk;
        this.f = c2830xf;
    }

    public static int a(Map map) {
        String str = (String) map.get("o");
        if (str == null) {
            return -1;
        }
        if ("p".equalsIgnoreCase(str)) {
            return 7;
        }
        if ("l".equalsIgnoreCase(str)) {
            return 6;
        }
        return "c".equalsIgnoreCase(str) ? 14 : -1;
    }

    public static Uri b(Context context, P4 p4, Uri uri, View view, Activity activity, C2067fq c2067fq) {
        if (p4 != null) {
            try {
                if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Xb)).booleanValue() || c2067fq == null) {
                    if (p4.b(uri)) {
                        return p4.a(uri, context, view, activity);
                    }
                } else if (p4.b(uri)) {
                    return c2067fq.a(uri, context, view, activity);
                }
            } catch (zzavm unused) {
            } catch (Exception e) {
                com.google.android.gms.ads.internal.j.C.h.h("OpenGmsgHandler.maybeAddClickSignalsToUri", e);
            }
        }
        return uri;
    }

    public static Uri c(Uri uri) {
        try {
            if (uri.getQueryParameter("aclk_ms") != null) {
                return uri.buildUpon().appendQueryParameter("aclk_upms", String.valueOf(SystemClock.uptimeMillis())).build();
            }
        } catch (UnsupportedOperationException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error adding click uptime parameter to url: ".concat(String.valueOf(uri.toString())), e);
        }
        return uri;
    }

    public final void d(Context context, String str, String str2) {
        C2107gm c2107gm = this.e;
        c2107gm.a(str);
        Hk hk = this.b;
        if (hk != null) {
            AbstractC2543qs.p("dialog_not_shown_reason", str2);
            BinderC2408nm.e4(context, hk, c2107gm, str, "dialog_not_shown", Gu.d(1, new Object[]{"dialog_not_shown_reason", str2}, null));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) {
        C2830xf c2830xf;
        InterfaceC1582a interfaceC1582a = (InterfaceC1582a) obj;
        String str = (String) map.get("u");
        HashMap map2 = new HashMap();
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) interfaceC1582a;
        if (interfaceC2529qe.e() != null) {
            map2 = interfaceC2529qe.e().w0;
        }
        String strU = AbstractC1795We.u(str, interfaceC2529qe.getContext(), true, map2);
        String str2 = (String) map.get("a");
        if (str2 == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Action missing from an open GMSG.");
            return;
        }
        com.google.android.gms.ads.internal.a aVar = this.a;
        if (aVar != null && !aVar.b()) {
            aVar.a(strU);
        } else {
            com.google.common.util.concurrent.e eVarA = (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.aa)).booleanValue() && (c2830xf = this.f) != null && C2830xf.b(strU)) ? c2830xf.a(strU, C1614q.f.e) : AbstractC2025es.E(strU);
            eVarA.a(new Qv(0, eVarA, new com.quizlet.data.repository.progress.b(this, map, interfaceC1582a, str2)), this.h);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:47:0x0153, code lost:
    
        r6 = r13;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0162  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(com.google.android.gms.ads.internal.client.InterfaceC1582a r17, java.util.Map r18, boolean r19, java.lang.String r20, boolean r21, boolean r22) {
        /*
            Method dump skipped, instructions count: 409
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2689u9.f(com.google.android.gms.ads.internal.client.a, java.util.Map, boolean, java.lang.String, boolean, boolean):void");
    }

    public final void g(boolean z) {
        C2397nb c2397nb = this.d;
        if (c2397nb != null) {
            c2397nb.E(z);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0075, code lost:
    
        if (((java.lang.Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(com.google.android.gms.internal.ads.AbstractC2773w7.A8)).booleanValue() != false) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00ea, code lost:
    
        if ((android.os.Build.VERSION.SDK_INT < 33 ? ((java.lang.Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(com.google.android.gms.internal.ads.AbstractC2773w7.v8)).booleanValue() : ((java.lang.Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(com.google.android.gms.internal.ads.AbstractC2773w7.u8)).booleanValue()) != false) goto L58;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(com.google.android.gms.ads.internal.client.InterfaceC1582a r10, android.content.Context r11, java.lang.String r12, java.lang.String r13) throws java.lang.IllegalAccessException, java.lang.InstantiationException, java.lang.IllegalArgumentException, com.google.android.gms.ads.internal.overlay.e, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 384
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2689u9.h(com.google.android.gms.ads.internal.client.a, android.content.Context, java.lang.String, java.lang.String):boolean");
    }

    public final void i(int i) {
        Hk hk;
        String str;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.D4)).booleanValue() || (hk = this.b) == null) {
            return;
        }
        Fi fiA = hk.a();
        fiA.o("action", "cct_action");
        switch (i) {
            case 2:
                str = "CONTEXT_NOT_AN_ACTIVITY";
                break;
            case 3:
                str = "CONTEXT_NULL";
                break;
            case 4:
                str = "CCT_NOT_SUPPORTED";
                break;
            case 5:
                str = "CCT_READY_TO_OPEN";
                break;
            case 6:
                str = "ACTIVITY_NOT_FOUND";
                break;
            case 7:
                str = "EMPTY_URL";
                break;
            case 8:
                str = "UNKNOWN";
                break;
            case 9:
                str = "WRONG_EXP_SETUP";
                break;
            default:
                str = "OPT_OUT";
                break;
        }
        fiA.o("cct_open_status", str);
        fiA.x();
    }
}
