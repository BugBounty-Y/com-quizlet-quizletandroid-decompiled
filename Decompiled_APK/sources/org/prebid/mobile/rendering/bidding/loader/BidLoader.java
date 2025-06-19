package org.prebid.mobile.rendering.bidding.loader;

import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.s0;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.infra.legacysyncengine.tasks.parse.b;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.api.data.AdFormat;
import org.prebid.mobile.api.exceptions.AdException;
import org.prebid.mobile.configuration.AdUnitConfiguration;
import org.prebid.mobile.rendering.bidding.listeners.BidRequesterListener;
import org.prebid.mobile.rendering.models.openrtb.BidRequest;
import org.prebid.mobile.rendering.networking.BaseNetworkTask;
import org.prebid.mobile.rendering.networking.ResponseHandler;
import org.prebid.mobile.rendering.networking.modelcontrollers.BidRequester;
import org.prebid.mobile.rendering.networking.parameters.AdRequestInput;
import org.prebid.mobile.rendering.networking.parameters.AppInfoParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.BasicParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.DeviceInfoParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.GeoLocationParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.NetworkParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.ParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.UserConsentParameterBuilder;
import org.prebid.mobile.rendering.networking.parameters.UserParameters$ConnectionType;
import org.prebid.mobile.rendering.networking.urlBuilder.BidPathBuilder;
import org.prebid.mobile.rendering.networking.urlBuilder.BidUrlComponents;
import org.prebid.mobile.rendering.networking.urlBuilder.URLBuilder;
import org.prebid.mobile.rendering.sdk.InitializationNotifier;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;
import org.prebid.mobile.rendering.sdk.deviceData.managers.DeviceInfoImpl;
import org.prebid.mobile.rendering.sdk.deviceData.managers.NetworkConnectionInfoManager;
import org.prebid.mobile.rendering.utils.helpers.AdvertisingIdManager;
import org.prebid.mobile.rendering.utils.helpers.AppInfoManager;
import org.prebid.mobile.rendering.utils.helpers.ExternalViewerUtils;
import org.prebid.mobile.rendering.utils.helpers.RefreshTimerTask;
import org.prebid.mobile.rendering.views.browser.AdBrowserActivity;

/* loaded from: classes3.dex */
public class BidLoader {
    public static boolean h = false;
    public final AdUnitConfiguration a;
    public BidRequester b;
    public final BidRequesterListener d;
    public s0 e;
    public final ResponseHandler f = new AnonymousClass1();
    public final RefreshTimerTask g = new RefreshTimerTask(new b(this, 29));
    public final AtomicBoolean c = new AtomicBoolean();

    /* renamed from: org.prebid.mobile.rendering.bidding.loader.BidLoader$1, reason: invalid class name */
    public class AnonymousClass1 implements ResponseHandler {
        public AnonymousClass1() {
        }

        @Override // org.prebid.mobile.rendering.networking.ResponseHandler
        public final void a(Exception exc) {
            BidLoader.a(BidLoader.this, exc.getMessage());
        }

        /* JADX WARN: Removed duplicated region for block: B:20:0x0092  */
        @Override // org.prebid.mobile.rendering.networking.ResponseHandler
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public final void b(org.prebid.mobile.rendering.networking.BaseNetworkTask.GetUrlResult r12) {
            /*
                Method dump skipped, instructions count: 407
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.bidding.loader.BidLoader.AnonymousClass1.b(org.prebid.mobile.rendering.networking.BaseNetworkTask$GetUrlResult):void");
        }

        @Override // org.prebid.mobile.rendering.networking.ResponseHandler
        public final void c(String str) {
            BidLoader.a(BidLoader.this, str);
        }
    }

    public BidLoader(AdUnitConfiguration adUnitConfiguration, BidRequesterListener bidRequesterListener) {
        this.a = adUnitConfiguration;
        this.d = bidRequesterListener;
    }

    public static void a(BidLoader bidLoader, String str) {
        bidLoader.getClass();
        LogUtil.b("BidLoader", "Invalid bid response: " + str);
        bidLoader.c.set(false);
        BidRequesterListener bidRequesterListener = bidLoader.d;
        if (bidRequesterListener != null) {
            bidLoader.c();
            bidRequesterListener.a(new AdException("SDK internal error", AbstractC0147y.d("Invalid bid response: ", str)));
            return;
        }
        LogUtil.e(5, "BidLoader", "onFailedToLoad: Listener is null.");
        LogUtil.e(3, "BidLoader", "Cancel refresh timer");
        Handler handler = bidLoader.g.a;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
        }
    }

    public final void b() {
        boolean zA;
        if (this.d == null) {
            LogUtil.b("BidLoader", "Listener is null");
            return;
        }
        AdUnitConfiguration adUnitConfiguration = this.a;
        if (adUnitConfiguration == null) {
            LogUtil.b("BidLoader", "No ad request configuration to load");
            return;
        }
        int i = PrebidMobile.a;
        if (PrebidContextHolder.a() == null || !InitializationNotifier.b) {
            LogUtil.b("BidLoader", "SDK wasn't initialized. Context is null.");
            return;
        }
        AtomicBoolean atomicBoolean = this.c;
        if (!atomicBoolean.compareAndSet(false, true)) {
            LogUtil.b("BidLoader", "Previous load is in progress. Load() ignored.");
            return;
        }
        atomicBoolean.set(true);
        String string = "";
        if (this.b == null) {
            AdRequestInput adRequestInput = new AdRequestInput();
            ResponseHandler responseHandler = this.f;
            BidRequester bidRequester = new BidRequester();
            bidRequester.a = "";
            bidRequester.b = adUnitConfiguration;
            Context contextA = PrebidContextHolder.a();
            if (contextA != null) {
                contextA.getResources();
            }
            if (contextA == null) {
                LogUtil.e(3, "ExternalViewerUtils", "isBrowserActivityCallable(): returning false. Context is null");
                zA = false;
            } else {
                zA = ExternalViewerUtils.a(contextA, new Intent(contextA, (Class<?>) AdBrowserActivity.class));
            }
            ArrayList arrayList = new ArrayList();
            arrayList.add(new BasicParameterBuilder(adUnitConfiguration, zA));
            arrayList.add(new GeoLocationParameterBuilder());
            arrayList.add(new AppInfoParameterBuilder());
            DeviceInfoParameterBuilder deviceInfoParameterBuilder = new DeviceInfoParameterBuilder();
            deviceInfoParameterBuilder.a = adUnitConfiguration;
            arrayList.add(deviceInfoParameterBuilder);
            arrayList.add(new NetworkParameterBuilder());
            arrayList.add(new UserConsentParameterBuilder());
            bidRequester.c = new URLBuilder(new BidPathBuilder(), new ArrayList(arrayList), adRequestInput);
            bidRequester.d = responseHandler;
            bidRequester.a = "bidrequest";
            this.b = bidRequester;
        }
        BidRequester bidRequester2 = this.b;
        boolean zIsEmpty = TextUtils.isEmpty(bidRequester2.b.h);
        ResponseHandler responseHandler2 = bidRequester2.d;
        if (zIsEmpty) {
            if (responseHandler2 != null) {
                ((AnonymousClass1) responseHandler2).c("No configuration id specified.");
                return;
            }
            return;
        }
        if (PrebidContextHolder.a() == null) {
            bidRequester2.a("Context is null", "Context is null. Can't continue with ad request");
            return;
        }
        DeviceInfoImpl deviceInfoImpl = ManagersResolver.a().a;
        if (deviceInfoImpl == null || deviceInfoImpl.a() == null || deviceInfoImpl.a().checkCallingOrSelfPermission("android.permission.INTERNET") != 0) {
            bidRequester2.a("Either Prebid DeviceManager is not initialized or android.permission.INTERNET is not specified. Please check", "Internet permission not granted");
        } else {
            NetworkConnectionInfoManager networkConnectionInfoManager = ManagersResolver.a().c;
            if (networkConnectionInfoManager == null || networkConnectionInfoManager.b() == UserParameters$ConnectionType.a) {
                bidRequester2.a("Either Prebid networkManager is not initialized or Device is offline. Please check the internet connection", "No internet connection detected");
            } else {
                URLBuilder uRLBuilder = bidRequester2.c;
                AdRequestInput adRequestInput2 = uRLBuilder.b;
                AdRequestInput adRequestInput3 = new AdRequestInput();
                try {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    new ObjectOutputStream(byteArrayOutputStream).writeObject(adRequestInput2.a);
                    adRequestInput3.a = (BidRequest) new ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray())).readObject();
                } catch (Exception unused) {
                    LogUtil.b("AdRequestInput", "Failed to make deep copy of bid request");
                    adRequestInput3 = null;
                }
                Iterator it2 = uRLBuilder.a.iterator();
                while (it2.hasNext()) {
                    ((ParameterBuilder) it2.next()).a(adRequestInput3);
                }
                String str = PrebidMobile.c.a;
                BidUrlComponents bidUrlComponents = new BidUrlComponents(str, adRequestInput3);
                BaseNetworkTask.GetUrlParams getUrlParams = new BaseNetworkTask.GetUrlParams();
                getUrlParams.a = str;
                try {
                    JSONObject jSONObjectB = adRequestInput3.a.b();
                    if (jSONObjectB.length() > 0) {
                        string = jSONObjectB.toString();
                    }
                } catch (Exception unused2) {
                    LogUtil.b("BidUrlComponents", "Failed to add OpenRTB query arg");
                }
                getUrlParams.b = string;
                getUrlParams.e = "POST";
                getUrlParams.d = AppInfoManager.a;
                getUrlParams.c = bidRequester2.a;
                try {
                    bidUrlComponents.a.a.b();
                } catch (JSONException unused3) {
                }
                new BaseNetworkTask(responseHandler2).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, getUrlParams);
            }
        }
        if (System.currentTimeMillis() - AdvertisingIdManager.a < 60000) {
            LogUtil.e(3, "AdvertisingIdManager", "Skipping advertising id fetching.");
            return;
        }
        try {
            AdvertisingIdManager.a = System.currentTimeMillis();
            AdvertisingIdManager.FetchTask fetchTask = new AdvertisingIdManager.FetchTask();
            fetchTask.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, new Void[0]);
            new Handler(Looper.getMainLooper()).postDelayed(new q(fetchTask, 26), 3000L);
        } catch (Throwable th) {
            LogUtil.b("AdvertisingIdManager", "Failed to init Google advertising id: " + Log.getStackTraceString(th) + "\nDid you add necessary dependencies?");
        }
    }

    public final void c() {
        LogUtil.e(3, "BidLoader", "Schedule refresh timer");
        AdUnitConfiguration adUnitConfiguration = this.a;
        if (adUnitConfiguration != null) {
            if (adUnitConfiguration.m.contains(AdFormat.a)) {
                int i = adUnitConfiguration.c;
                if (i == Integer.MAX_VALUE || i <= 0) {
                    LogUtil.e(3, "BidLoader", "setupRefreshTimer(): refreshTimeMillis is: " + i + ". Skipping refresh timer initialization");
                    return;
                }
                int iMax = Math.max(i, 1000);
                RefreshTimerTask refreshTimerTask = this.g;
                Handler handler = refreshTimerTask.a;
                if (handler != null) {
                    handler.removeCallbacksAndMessages(null);
                }
                if (iMax > 0) {
                    long j = iMax;
                    Handler handler2 = refreshTimerTask.a;
                    if (handler2 != null) {
                        handler2.postDelayed(refreshTimerTask.c, j);
                        return;
                    }
                    return;
                }
                return;
            }
        }
        LogUtil.e(3, "BidLoader", "setupRefreshTimer: Canceled. AdConfiguration is null or AdType is not Banner");
    }
}
