package com.quizlet.quizletandroid.managers;

import android.content.Context;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.eventlogger.events.CurrentUserEvent;
import java.util.HashMap;

/* loaded from: classes3.dex */
public final class c {
    public g a;
    public Context b;
    public boolean c;
    public boolean d;
    public CurrentUserEvent e;

    public final void a(boolean z) {
        String string;
        if (!z) {
            com.google.ads.conversiontracking.g gVarA = com.google.ads.conversiontracking.g.a(this.b);
            synchronized (gVarA.e) {
                gVarA.f.add("943230862");
                gVarA.g.remove("943230862");
            }
            return;
        }
        com.google.ads.conversiontracking.g gVarA2 = com.google.ads.conversiontracking.g.a(this.b);
        synchronized (gVarA2.e) {
            gVarA2.f.remove("943230862");
        }
        gVarA2.d();
        if (this.d) {
            return;
        }
        Context context = this.b;
        com.google.ads.conversiontracking.q qVar = new com.google.ads.conversiontracking.q();
        qVar.a = "943230862";
        qVar.c = 3;
        qVar.d = "CCjDCPL5yWQQjp_iwQM";
        qVar.e = "0.00";
        com.google.ads.conversiontracking.g gVarA3 = com.google.ads.conversiontracking.g.a(context);
        gVarA3.d();
        qVar.b = gVarA3.g.containsKey("943230862");
        HashMap map = com.google.ads.conversiontracking.r.a;
        int[] iArr = com.google.ads.conversiontracking.p.a;
        int i = iArr[AbstractC0147y.k(qVar.c)];
        String str = i != 1 ? i != 2 ? "google_nonrepeatable_conversion" : "iap_nonrepeatable_conversion" : "doubleclick_nonrepeatable_conversion";
        int i2 = iArr[AbstractC0147y.k(qVar.c)];
        if (com.google.ads.conversiontracking.r.d(context, str, i2 != 1 ? i2 != 2 ? qVar.d : "google_iap_ping:null" : qVar.a, false)) {
            try {
                HashMap map2 = com.google.ads.conversiontracking.r.a;
                synchronized (map2) {
                    string = (String) map2.get("943230862");
                }
                if (string == null) {
                    string = context.getSharedPreferences("google_conversion_click_referrer", 0).getString("943230862", "");
                }
                qVar.f = com.quizlet.data.interactor.school.e.a(string);
                new Thread(new com.google.ads.conversiontracking.b(context, qVar, true, false, true)).start();
            } catch (Exception e) {
                Log.e("GoogleConversionReporter", "Error sending ping", e);
            }
        }
        this.d = true;
    }

    public final void b() {
        CurrentUserEvent currentUserEvent = this.e;
        boolean z = currentUserEvent != null && currentUserEvent.c;
        DBUser currentUser = currentUserEvent == null ? null : currentUserEvent.getCurrentUser();
        if (!z) {
            a(true);
        } else if (currentUser != null) {
            CurrentUserEvent currentUserEvent2 = this.a.d;
            DBUser currentUser2 = currentUserEvent2 != null ? currentUserEvent2.getCurrentUser() : null;
            e eVar = e.b;
            a(!((currentUser2 == null ? e.a : currentUser2.getIsUnderAge() ? eVar : e.c) == eVar));
        }
    }
}
