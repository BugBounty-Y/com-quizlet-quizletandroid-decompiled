package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import android.webkit.WebView;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Iterator;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.sm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2622sm {
    public final Context a;
    public final VersionInfoParcel b;
    public final Vp c;
    public final InterfaceC2529qe d;
    public final Hk e;
    public com.quizlet.data.repository.studysetwithcreatorinclass.g f;

    public C2622sm(Context context, VersionInfoParcel versionInfoParcel, Vp vp, InterfaceC2529qe interfaceC2529qe, Hk hk) {
        this.a = context;
        this.b = versionInfoParcel;
        this.c = vp;
        this.d = interfaceC2529qe;
        this.e = hk;
    }

    public final synchronized void a() {
        InterfaceC2529qe interfaceC2529qe;
        if (this.f == null || (interfaceC2529qe = this.d) == null) {
            return;
        }
        interfaceC2529qe.j("onSdkImpression", Gu.g);
    }

    public final synchronized void b() {
        InterfaceC2529qe interfaceC2529qe;
        try {
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.f;
            if (gVar == null || (interfaceC2529qe = this.d) == null) {
                return;
            }
            Iterator it2 = interfaceC2529qe.u0().iterator();
            while (it2.hasNext()) {
                View view = (View) it2.next();
                com.google.android.gms.ads.internal.j.C.x.getClass();
                C2147hi.p(new RunnableC2793wl(2, gVar, view));
            }
            interfaceC2529qe.j("onSdkLoaded", Gu.g);
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized boolean c() {
        InterfaceC2529qe interfaceC2529qe;
        Vp vp = this.c;
        if (vp.T) {
            C2601s7 c2601s7 = AbstractC2773w7.k5;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                if (((Boolean) rVar.c.a(AbstractC2773w7.n5)).booleanValue() && (interfaceC2529qe = this.d) != null) {
                    if (this.f != null) {
                        com.google.android.gms.ads.internal.util.client.i.h("Omid javascript session service already started for ad.");
                        return false;
                    }
                    Context context = this.a;
                    com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                    jVar.x.getClass();
                    if (!C2147hi.l(context)) {
                        com.google.android.gms.ads.internal.util.client.i.h("Unable to initialize omid.");
                        return false;
                    }
                    C2881yn c2881yn = vp.V;
                    c2881yn.getClass();
                    if (((JSONObject) c2881yn.b).optBoolean((String) rVar.c.a(AbstractC2773w7.p5), true)) {
                        VersionInfoParcel versionInfoParcel = this.b;
                        C2147hi c2147hi = jVar.x;
                        WebView webViewN = interfaceC2529qe.n();
                        c2147hi.getClass();
                        com.quizlet.data.repository.studysetwithcreatorinclass.g gVarE = C2147hi.e(versionInfoParcel, webViewN);
                        if (((Boolean) rVar.c.a(AbstractC2773w7.o5)).booleanValue()) {
                            Hk hk = this.e;
                            String str = gVarE != null ? "1" : "0";
                            Fi fiA = hk.a();
                            fiA.o("omid_js_session_success", str);
                            fiA.x();
                        }
                        if (gVarE == null) {
                            com.google.android.gms.ads.internal.util.client.i.h("Unable to create javascript session service.");
                            return false;
                        }
                        com.google.android.gms.ads.internal.util.client.i.g("Created omid javascript session service.");
                        this.f = gVarE;
                        interfaceC2529qe.G0(this);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
