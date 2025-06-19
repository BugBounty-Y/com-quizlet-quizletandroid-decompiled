package org.prebid.mobile.rendering.sdk;

import android.app.Application;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.api.rendering.PrebidRenderer;
import org.prebid.mobile.api.rendering.pluginrenderer.PrebidMobilePluginRegister;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;

/* loaded from: classes3.dex */
public abstract class SdkInitializer {

    public static class UserConsentFetcherTask implements Runnable {
        @Override // java.lang.Runnable
        public final void run() {
            UserConsentManager userConsentManager = ManagersResolver.ManagersResolverHolder.a.d;
            userConsentManager.getClass();
            String[] strArr = UserConsentManager.i;
            for (int i = 0; i < 6; i++) {
                userConsentManager.b(userConsentManager.h, strArr[i]);
            }
        }
    }

    public static void a(Context context, com.quizlet.infra.legacysyncengine.models.serializers.a aVar) {
        int i = PrebidMobile.a;
        if ((PrebidContextHolder.a() == null || !InitializationNotifier.b) && !InitializationNotifier.c) {
            InitializationNotifier initializationNotifier = new InitializationNotifier();
            initializationNotifier.a = aVar;
            InitializationNotifier.c = true;
            if (!(context instanceof Application)) {
                context = context != null ? context.getApplicationContext() : null;
            }
            if (context == null) {
                new Handler(Looper.getMainLooper()).post(new a(initializationNotifier, "Context must be not null!", 0));
                return;
            }
            LogUtil.e(3, "SdkInitializer", "Initializing Prebid SDK");
            PrebidContextHolder.a = new WeakReference(context);
            LogUtil.a = -1;
            try {
                PrebidRenderer prebidRenderer = new PrebidRenderer();
                PrebidMobilePluginRegister prebidMobilePluginRegister = PrebidMobilePluginRegister.b;
                prebidMobilePluginRegister.getClass();
                HashMap map = prebidMobilePluginRegister.a;
                if (map.containsKey("PrebidRenderer")) {
                    LogUtil.e(3, "PrebidMobilePluginRegister", "New plugin renderer with namePrebidRendererwill replace the previous one with same name");
                }
                map.put("PrebidRenderer", prebidRenderer);
                AppInfoManager.b(context);
                try {
                    com.iab.omid.library.prebidorg.a.a(context);
                } catch (Throwable th) {
                    LogUtil.b("OmAdSessionManager", "Did you add omsdk-android.aar? Failed to init openMeasurementSDK: " + Log.getStackTraceString(th));
                }
                ManagersResolver.ManagersResolverHolder.a.b(context);
                JSLibraryManager.b(context).a();
                new Thread(new b(initializationNotifier, 1)).start();
            } catch (Throwable th2) {
                new Handler(Looper.getMainLooper()).post(new a(initializationNotifier, "Exception during initialization: " + th2.getMessage() + "\n" + Log.getStackTraceString(th2), 0));
            }
        }
    }
}
