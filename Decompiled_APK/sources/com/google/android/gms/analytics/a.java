package com.google.android.gms.analytics;

import android.util.Log;
import com.google.android.gms.internal.gtm.zzeg;
import com.google.android.gms.internal.gtm.zzeh;
import com.google.android.gms.internal.gtm.zzen;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class a extends com.quizlet.data.repository.course.membership.c {
    public static ArrayList g = new ArrayList();
    public boolean d;
    public boolean e;
    public boolean f;

    public final void t(b bVar) {
        zzen.zzc(bVar);
        if (this.f) {
            return;
        }
        zzeg zzegVar = zzeh.zzb;
        Log.i((String) zzegVar.zzb(), "GoogleAnalytics.setLogger() is deprecated. To enable debug logging, please run:\nadb shell setprop log.tag." + ((String) zzegVar.zzb()) + " DEBUG");
        this.f = true;
    }
}
