package com.iab.omid.library.prebidorg;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Handler;
import androidx.camera.camera2.internal.compat.workaround.e;
import com.google.android.gms.ads.internal.util.E;
import com.google.android.gms.internal.ads.Sr;
import com.google.mlkit.common.sdkinternal.b;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import com.quizlet.data.repository.searchexplanations.c;

/* loaded from: classes2.dex */
public abstract class a {
    public static final e a = new e(12, false);

    public static void a(Context context) {
        e eVar = a;
        Context applicationContext = context.getApplicationContext();
        if (applicationContext == null) {
            throw new IllegalArgumentException("Application Context cannot be null");
        }
        if (eVar.b) {
            return;
        }
        eVar.b = true;
        if (c.d == null) {
            c.d = new c(new h(21), new com.google.mlkit.common.sdkinternal.model.a(21));
        }
        c cVar = c.d;
        Object obj = cVar.b;
        new com.iab.omid.library.prebidorg.devicevolume.a(new Handler(), applicationContext, new b(21), cVar);
        com.iab.omid.library.prebidorg.internal.b bVar = com.iab.omid.library.prebidorg.internal.b.e;
        boolean z = applicationContext instanceof Application;
        if (z) {
            ((Application) applicationContext).registerActivityLifecycleCallbacks(bVar);
        }
        int i = com.iab.omid.library.prebidorg.utils.a.a;
        float f = applicationContext.getResources().getDisplayMetrics().density;
        int i2 = com.iab.omid.library.prebidorg.utils.a.a;
        int i3 = com.iab.omid.library.prebidorg.utils.a.a;
        applicationContext.registerReceiver(new E(4), new IntentFilter("android.media.action.HDMI_AUDIO_PLUG"));
        applicationContext.getApplicationContext();
        com.iab.omid.library.prebidorg.internal.a aVar = com.iab.omid.library.prebidorg.internal.a.f;
        if (aVar.c) {
            return;
        }
        Sr sr = aVar.d;
        sr.getClass();
        if (z) {
            ((Application) applicationContext).registerActivityLifecycleCallbacks(sr);
        }
        sr.d = aVar;
        sr.b = true;
        ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
        ActivityManager.getMyMemoryState(runningAppProcessInfo);
        boolean z2 = runningAppProcessInfo.importance == 100;
        sr.c = z2;
        aVar.e = z2;
        aVar.c = true;
    }
}
