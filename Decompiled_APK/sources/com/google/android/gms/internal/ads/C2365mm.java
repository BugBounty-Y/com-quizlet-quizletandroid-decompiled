package com.google.android.gms.internal.ads;

import android.app.AlertDialog;
import android.webkit.WebView;
import java.util.Objects;
import java.util.Timer;
import java.util.TimerTask;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;

/* renamed from: com.google.android.gms.internal.ads.mm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2365mm extends TimerTask {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Timer b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public C2365mm(AlertDialog alertDialog, Timer timer, com.google.android.gms.ads.internal.overlay.d dVar) {
        this.c = alertDialog;
        this.b = timer;
        this.d = dVar;
    }

    @Override // java.util.TimerTask, java.lang.Runnable
    public final void run() {
        Timer timer = this.b;
        Object obj = this.d;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                ((AlertDialog) obj2).dismiss();
                timer.cancel();
                com.google.android.gms.ads.internal.overlay.d dVar = (com.google.android.gms.ads.internal.overlay.d) obj;
                if (dVar != null) {
                    dVar.b();
                    return;
                }
                return;
            default:
                com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = (com.quizlet.data.repository.studysetwithcreatorinclass.g) obj2;
                gVar.getClass();
                int i = androidx.webkit.i.a;
                if (!androidx.webkit.internal.s.e.b()) {
                    throw androidx.webkit.internal.s.a();
                }
                ((WebViewProviderBoundaryInterface) androidx.webkit.i.b((WebView) gVar.c).b).removeWebMessageListener("omidJsSessionService");
                C2743ve c2743ve = (C2743ve) ((Os) obj).b;
                com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
                ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
                Objects.requireNonNull(viewTreeObserverOnGlobalLayoutListenerC2829xe);
                b.post(new RunnableC2700ue(viewTreeObserverOnGlobalLayoutListenerC2829xe, 0));
                timer.cancel();
                return;
        }
    }

    public C2365mm(com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, Os os, Timer timer) {
        this.d = os;
        this.b = timer;
        this.c = gVar;
    }
}
