package com.iab.omid.library.amazon;

import android.app.ActivityManager;
import android.app.Application;
import android.app.UiModeManager;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Handler;
import android.view.WindowManager;
import androidx.camera.camera2.internal.compat.workaround.e;
import com.airbnb.lottie.animation.keyframe.c;
import com.google.android.gms.ads.internal.util.E;
import com.google.android.gms.internal.ads.Sr;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3747w;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3763y;
import com.iab.omid.library.amazon.internal.b;
import com.iab.omid.library.amazon.internal.g;

/* loaded from: classes2.dex */
public abstract class a {
    public static final e a = new e(11, false);

    public static void a(Context context) {
        e eVar = a;
        Context applicationContext = context.getApplicationContext();
        AbstractC3763y.a(applicationContext, "Application Context cannot be null");
        if (eVar.b) {
            return;
        }
        eVar.b = true;
        c cVarD = c.d();
        Object obj = cVarD.b;
        cVarD.c = new com.iab.omid.library.amazon.devicevolume.a(new Handler(), applicationContext, new com.google.android.material.shape.e(21), cVarD);
        b bVar = b.e;
        boolean z = applicationContext instanceof Application;
        if (z) {
            ((Application) applicationContext).registerActivityLifecycleCallbacks(bVar);
        }
        AbstractC3747w.a = (UiModeManager) applicationContext.getSystemService("uimode");
        WindowManager windowManager = com.iab.omid.library.amazon.utils.b.a;
        com.iab.omid.library.amazon.utils.b.c = applicationContext.getResources().getDisplayMetrics().density;
        com.iab.omid.library.amazon.utils.b.a = (WindowManager) applicationContext.getSystemService("window");
        applicationContext.registerReceiver(new E(3), new IntentFilter("android.media.action.HDMI_AUDIO_PLUG"));
        g.b.a = applicationContext.getApplicationContext();
        com.iab.omid.library.amazon.internal.a aVar = com.iab.omid.library.amazon.internal.a.f;
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
        sr.c = runningAppProcessInfo.importance == 100;
        aVar.e = sr.c;
        aVar.c = true;
    }
}
