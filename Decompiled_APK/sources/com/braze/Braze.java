package com.braze;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.braze.configuration.BrazeConfig;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.configuration.RuntimeAppConfigurationProvider;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.enums.BrazePushEventType;
import com.braze.events.BrazePushEvent;
import com.braze.events.BrazeUserChangeEvent;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.events.FeedUpdatedEvent;
import com.braze.events.IEventSubscriber;
import com.braze.events.IValueCallback;
import com.braze.events.InAppMessageEvent;
import com.braze.events.SdkDataWipeEvent;
import com.braze.images.IBrazeImageLoader;
import com.braze.managers.C1488a;
import com.braze.managers.C1489b;
import com.braze.managers.C1500m;
import com.braze.managers.C1506t;
import com.braze.managers.C1507u;
import com.braze.managers.c0;
import com.braze.managers.t0;
import com.braze.managers.u0;
import com.braze.models.cards.Card;
import com.braze.models.outgoing.BrazeProperties;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.storage.a0;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.PermissionUtils;
import com.braze.support.StringUtils;
import com.braze.support.ValidationUtils;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.Z;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class Braze {
    private static final Set<String> NECESSARY_BRAZE_SDK_PERMISSIONS;
    private static boolean areOutboundNetworkRequestsOffline;
    private static final BrazeConfig clearConfigSentinel;
    private static IBrazeNotificationFactory customBrazeNotificationFactory;
    private static com.braze.managers.d0 deviceDataProvider;
    private static IBrazeEndpointProvider endpointProvider;
    private static final ReentrantLock endpointProviderLock;
    private static volatile Braze instance;
    private static final List<BrazeConfig> pendingConfigurations;
    private static a0 sdkEnablementProvider;
    private static boolean shouldMockNetworkRequestsAndDropEvents;
    private static boolean shouldRequestFrameworkListenToNetworkUpdates;
    private static com.braze.events.e staticExternalIEventMessenger;
    private Context applicationContext;
    private BrazeUser brazeUser;
    public BrazeConfigurationProvider configurationProvider;
    public com.braze.managers.e0 deviceIdProvider;
    private com.braze.events.e externalIEventMessenger;
    public IBrazeImageLoader imageLoader;
    private Boolean isApiKeyPresent;
    private boolean isInstanceStopped;
    private com.braze.configuration.e offlineUserStorageProvider;
    public com.braze.managers.i0 pushDeliveryManager;
    public com.braze.managers.g0 registrationDataProvider;
    public com.braze.managers.h0 udm;
    public static final Companion Companion = new Companion(null);
    private static final ReentrantLock brazeClassLock = new ReentrantLock();
    private static final Set<String> KNOWN_APP_CRAWLER_DEVICE_MODELS = Z.b("calypso appcrawler");

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String _get_isDisabled_$lambda$2() {
            return "SDK enablement provider was null. Returning SDK as enabled.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String _get_isDisabled_$lambda$3() {
            return "API key not present. Actions will not be performed on the SDK.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String _get_isDisabled_$lambda$4() {
            return "SDK is disabled. Actions will not be performed on the SDK.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String _set_outboundNetworkRequestsOffline_$lambda$0(boolean z) {
            return "Braze SDK outbound network requests are now ".concat(z ? "disabled" : "enabled");
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String disableSdk$lambda$23() {
            return "Stopping the SDK instance.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String disableSdk$lambda$24() {
            return "Disabling all network requests";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String enableMockNetworkRequestsAndDropEventsMode$lambda$21$lambda$19() {
            return "Braze network requests already being mocked. Note that events dispatched in this mode are dropped.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String enableMockNetworkRequestsAndDropEventsMode$lambda$21$lambda$20() {
            return "Braze network requests will be mocked. Events dispatchedin this mode will be dropped.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String enableMockNetworkRequestsAndDropEventsMode$lambda$22() {
            return "Attempt to enable mocking Braze network requests had no effect since getInstance() has already been called.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String enableSdk$lambda$25() {
            return "Setting SDK to enabled.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String enableSdk$lambda$26() {
            return "Enabling all network requests";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String getApiEndpoint$lambda$12$lambda$11$lambda$10() {
            return "Caught exception trying to get a Braze API endpoint from the BrazeEndpointProvider. Using the original URI";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String getConfiguredApiKey$lambda$7() {
            return "Caught exception while retrieving API key.";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String getInstance$lambda$6$lambda$5() {
            return "Created external messenger " + Braze.Companion.getStaticExternalIEventMessenger$android_sdk_base_release();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final a0 getSdkEnablementProvider(Context context) {
            a0 sdkEnablementProvider$android_sdk_base_release = getSdkEnablementProvider$android_sdk_base_release();
            if (sdkEnablementProvider$android_sdk_base_release != null) {
                return sdkEnablementProvider$android_sdk_base_release;
            }
            a0 a0Var = new a0(context);
            setSdkEnablementProvider$android_sdk_base_release(a0Var);
            return a0Var;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String requestTriggersIfInAppMessageTestPush$lambda$37() {
            return "Push contained key for fetching test triggers, fetching triggers.";
        }

        private static final Uri setConfiguredCustomEndpoint$lambda$33$lambda$32(String str, Uri brazeEndpoint) {
            String authority;
            Intrinsics.checkNotNullParameter(brazeEndpoint, "brazeEndpoint");
            Uri uri = Uri.parse(str);
            String scheme = uri.getScheme();
            boolean z = scheme == null || StringsKt.O(scheme) || (authority = uri.getAuthority()) == null || StringsKt.O(authority);
            Uri.Builder builder = new Uri.Builder();
            if (z || uri.getScheme() == null) {
                builder.scheme(brazeEndpoint.getScheme());
            } else {
                builder.scheme(uri.getScheme());
            }
            if (z) {
                builder.encodedAuthority(str);
            } else if (uri.getEncodedAuthority() != null) {
                builder.encodedAuthority(uri.getEncodedAuthority());
            } else {
                builder.encodedAuthority(brazeEndpoint.getEncodedAuthority());
            }
            if (z || uri.getPath() == null) {
                builder.path(brazeEndpoint.getPath());
            } else {
                builder.path(uri.getPath() + brazeEndpoint.getPath());
            }
            return builder.build();
        }

        private final boolean shouldAllowSingletonInitialization() {
            Braze braze = Braze.instance;
            if (braze == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new M(6), 6, (Object) null);
                return true;
            }
            if (braze.isInstanceStopped) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new M(7), 7, (Object) null);
                return true;
            }
            if (!Boolean.FALSE.equals(braze.isApiKeyPresent$android_sdk_base_release())) {
                return false;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new M(8), 7, (Object) null);
            return true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String shouldAllowSingletonInitialization$lambda$34() {
            return "The instance is null. Allowing instance initialization";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String shouldAllowSingletonInitialization$lambda$35() {
            return "The instance was stopped. Allowing instance initialization";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String shouldAllowSingletonInitialization$lambda$36() {
            return "No API key was found previously. Allowing instance initialization";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String stopInstance$lambda$38() {
            return "Shutting down all queued work on the Braze SDK";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String stopInstance$lambda$41$lambda$39() {
            return "Sending sdk data wipe event to external subscribers";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String stopInstance$lambda$41$lambda$40() {
            return "Shutting down the singleton work queue";
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static final String stopInstance$lambda$42() {
            return "Failed to shutdown queued work on the Braze SDK.";
        }

        public final void disableSdk(Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            getSdkEnablementProvider(context).b(true);
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.Priority priority = BrazeLogger.Priority.W;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new M(11), 6, (Object) null);
            stopInstance$android_sdk_base_release(false);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new C(22), 6, (Object) null);
            setOutboundNetworkRequestsOffline(true);
        }

        public final boolean enableMockNetworkRequestsAndDropEventsMode() {
            int i = 0;
            if (Braze.instance == null) {
                ReentrantLock reentrantLock = Braze.brazeClassLock;
                reentrantLock.lock();
                try {
                    if (Braze.instance == null) {
                        if (Braze.shouldMockNetworkRequestsAndDropEvents) {
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) Braze.Companion, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new M(i), 6, (Object) null);
                        } else {
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) Braze.Companion, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new M(4), 6, (Object) null);
                            Braze.shouldMockNetworkRequestsAndDropEvents = true;
                        }
                        reentrantLock.unlock();
                        return true;
                    }
                    Unit unit = Unit.a;
                    reentrantLock.unlock();
                } catch (Throwable th) {
                    reentrantLock.unlock();
                    throw th;
                }
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new M(5), 6, (Object) null);
            return false;
        }

        public final void enableSdk(Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.Priority priority = BrazeLogger.Priority.W;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new M(9), 6, (Object) null);
            getSdkEnablementProvider(context).b(false);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new M(10), 6, (Object) null);
            setOutboundNetworkRequestsOffline(false);
        }

        public final Uri getApiEndpoint(Uri brazeEndpoint) {
            Intrinsics.checkNotNullParameter(brazeEndpoint, "brazeEndpoint");
            ReentrantLock reentrantLock = Braze.endpointProviderLock;
            reentrantLock.lock();
            try {
                IBrazeEndpointProvider iBrazeEndpointProvider = Braze.endpointProvider;
                if (iBrazeEndpointProvider != null) {
                    try {
                        Uri configuredCustomEndpoint$lambda$33$lambda$32 = setConfiguredCustomEndpoint$lambda$33$lambda$32(((L) iBrazeEndpointProvider).b, brazeEndpoint);
                        if (configuredCustomEndpoint$lambda$33$lambda$32 != null) {
                            reentrantLock.unlock();
                            return configuredCustomEndpoint$lambda$33$lambda$32;
                        }
                    } catch (Exception e) {
                        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) Braze.Companion, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new M(1), 4, (Object) null);
                    }
                }
                reentrantLock.unlock();
                return brazeEndpoint;
            } catch (Throwable th) {
                reentrantLock.unlock();
                throw th;
            }
        }

        public final String getConfiguredApiKey(BrazeConfigurationProvider configurationProvider) {
            Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
            try {
                return configurationProvider.getBrazeApiKey().a;
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new M(2), 4, (Object) null);
                return null;
            }
        }

        public final IBrazeNotificationFactory getCustomBrazeNotificationFactory() {
            return Braze.customBrazeNotificationFactory;
        }

        public final Braze getInstance(Context context) {
            Intrinsics.checkNotNullParameter(context, "context");
            if (shouldAllowSingletonInitialization()) {
                ReentrantLock reentrantLock = Braze.brazeClassLock;
                reentrantLock.lock();
                try {
                    Companion companion = Braze.Companion;
                    if (companion.shouldAllowSingletonInitialization()) {
                        if (companion.getStaticExternalIEventMessenger$android_sdk_base_release() == null) {
                            companion.setStaticExternalIEventMessenger$android_sdk_base_release(new com.braze.events.d(new a0(context), false));
                            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) companion, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(21), 6, (Object) null);
                        }
                        Braze braze = new Braze(context);
                        braze.isInstanceStopped = false;
                        Braze.instance = braze;
                        reentrantLock.unlock();
                        return braze;
                    }
                    Unit unit = Unit.a;
                    reentrantLock.unlock();
                } catch (Throwable th) {
                    reentrantLock.unlock();
                    throw th;
                }
            }
            Braze braze2 = Braze.instance;
            Intrinsics.e(braze2, "null cannot be cast to non-null type com.braze.Braze");
            return braze2;
        }

        public final boolean getOutboundNetworkRequestsOffline() {
            return Braze.areOutboundNetworkRequestsOffline;
        }

        public final a0 getSdkEnablementProvider$android_sdk_base_release() {
            return Braze.sdkEnablementProvider;
        }

        public final com.braze.events.e getStaticExternalIEventMessenger$android_sdk_base_release() {
            return Braze.staticExternalIEventMessenger;
        }

        public final boolean isDisabled() {
            a0 sdkEnablementProvider$android_sdk_base_release = getSdkEnablementProvider$android_sdk_base_release();
            if (sdkEnablementProvider$android_sdk_base_release == null) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(27), 7, (Object) null);
                return false;
            }
            Braze braze = Braze.instance;
            if (braze != null && Boolean.FALSE.equals(braze.isApiKeyPresent$android_sdk_base_release())) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(28), 6, (Object) null);
                return true;
            }
            boolean z = sdkEnablementProvider$android_sdk_base_release.a.getBoolean("appboy_sdk_disabled", false);
            if (z) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(29), 6, (Object) null);
            }
            return z;
        }

        public final void requestTriggersIfInAppMessageTestPush$android_sdk_base_release(Intent intent, c0 brazeManager) {
            Intrinsics.checkNotNullParameter(intent, "intent");
            Intrinsics.checkNotNullParameter(brazeManager, "brazeManager");
            String stringExtra = intent.getStringExtra("ab_push_fetch_test_triggers_key");
            if (stringExtra == null || !stringExtra.equals("true")) {
                return;
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new M(3), 6, (Object) null);
            com.braze.models.outgoing.j jVar = new com.braze.models.outgoing.j();
            jVar.c = Boolean.TRUE;
            ((C1500m) brazeManager).a(jVar);
        }

        public final void setConfiguredCustomEndpoint$android_sdk_base_release(String str) {
            ReentrantLock reentrantLock = Braze.endpointProviderLock;
            reentrantLock.lock();
            try {
                Braze.Companion.setEndpointProvider(new L(str, 0));
                Unit unit = Unit.a;
            } finally {
                reentrantLock.unlock();
            }
        }

        public final void setEndpointProvider(IBrazeEndpointProvider iBrazeEndpointProvider) {
            ReentrantLock reentrantLock = Braze.endpointProviderLock;
            reentrantLock.lock();
            try {
                Braze.endpointProvider = iBrazeEndpointProvider;
                Unit unit = Unit.a;
            } finally {
                reentrantLock.unlock();
            }
        }

        public final void setOutboundNetworkRequestsOffline(boolean z) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1483i(z, 3), 6, (Object) null);
            ReentrantLock reentrantLock = Braze.brazeClassLock;
            reentrantLock.lock();
            try {
                Braze.areOutboundNetworkRequestsOffline = z;
                Braze braze = Braze.instance;
                if (braze != null) {
                    braze.setSyncPolicyOfflineStatus(z);
                    Unit unit = Unit.a;
                }
                reentrantLock.unlock();
            } catch (Throwable th) {
                reentrantLock.unlock();
                throw th;
            }
        }

        public final void setSdkEnablementProvider$android_sdk_base_release(a0 a0Var) {
            Braze.sdkEnablementProvider = a0Var;
        }

        public final void setStaticExternalIEventMessenger$android_sdk_base_release(com.braze.events.e eVar) {
            Braze.staticExternalIEventMessenger = eVar;
        }

        public final void stopInstance$android_sdk_base_release(boolean z) {
            try {
                BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C(23), 6, (Object) null);
                ReentrantLock reentrantLock = Braze.brazeClassLock;
                reentrantLock.lock();
                try {
                    BrazeCoroutineScope.cancelChildren();
                    Braze braze = Braze.instance;
                    if (braze != null) {
                        Companion companion = Braze.Companion;
                        BrazeLogger.brazelog$default(brazeLogger, (Object) companion, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(24), 6, (Object) null);
                        ((com.braze.events.d) braze.getExternalIEventMessenger$android_sdk_base_release()).b(new SdkDataWipeEvent(), SdkDataWipeEvent.class);
                        BrazeLogger.brazelog$default(brazeLogger, (Object) companion, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(25), 7, (Object) null);
                        com.braze.coroutine.f.a.a();
                        if (braze.udm != null) {
                            if (z) {
                                ((u0) braze.getUdm$android_sdk_base_release()).C.a();
                                ((u0) braze.getUdm$android_sdk_base_release()).z.a();
                                ((u0) braze.getUdm$android_sdk_base_release()).A.a();
                            }
                            com.braze.dispatch.f fVar = ((u0) braze.getUdm$android_sdk_base_release()).p;
                            synchronized (fVar) {
                                fVar.l = true;
                                fVar.b();
                                fVar.f();
                            }
                            com.braze.managers.z zVar = ((u0) braze.getUdm$android_sdk_base_release()).r;
                            zVar.b = true;
                            zVar.a.c = true;
                            ((u0) braze.getUdm$android_sdk_base_release()).x.unregisterGeofences();
                        }
                        braze.isInstanceStopped = true;
                    }
                    Unit unit = Unit.a;
                    reentrantLock.unlock();
                } catch (Throwable th) {
                    reentrantLock.unlock();
                    throw th;
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new C(26), 4, (Object) null);
            }
        }

        private Companion() {
        }
    }

    static {
        String[] elements = {"android.permission.ACCESS_NETWORK_STATE", "android.permission.INTERNET"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        NECESSARY_BRAZE_SDK_PERMISSIONS = C4933y.T(elements);
        endpointProviderLock = new ReentrantLock();
        shouldRequestFrameworkListenToNetworkUpdates = true;
        pendingConfigurations = new ArrayList();
        clearConfigSentinel = new BrazeConfig.Builder().build();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0051  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public Braze(android.content.Context r15) {
        /*
            r14 = this;
            java.lang.String r0 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r15, r0)
            r14.<init>()
            long r4 = java.lang.System.nanoTime()
            com.braze.support.BrazeLogger r6 = com.braze.support.BrazeLogger.INSTANCE
            androidx.lifecycle.compose.f r11 = new androidx.lifecycle.compose.f
            r0 = 29
            r11.<init>(r0)
            r9 = 0
            r10 = 0
            r8 = 0
            r12 = 7
            r13 = 0
            r7 = r14
            com.braze.support.BrazeLogger.brazelog$default(r6, r7, r8, r9, r10, r11, r12, r13)
            android.content.Context r0 = r15.getApplicationContext()
            r7.applicationContext = r0
            java.lang.String r0 = android.os.Build.MODEL
            if (r0 == 0) goto L51
            java.util.Set<java.lang.String> r1 = com.braze.Braze.KNOWN_APP_CRAWLER_DEVICE_MODELS
            java.util.Locale r2 = java.util.Locale.ROOT
            java.lang.String r0 = r0.toLowerCase(r2)
            java.lang.String r2 = "toLowerCase(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            boolean r0 = r1.contains(r0)
            if (r0 == 0) goto L51
            com.braze.support.BrazeLogger$Priority r8 = com.braze.support.BrazeLogger.Priority.I
            com.braze.A r11 = new com.braze.A
            r0 = 7
            r11.<init>(r0)
            r9 = 0
            r10 = 0
            r12 = 6
            r13 = 0
            com.braze.support.BrazeLogger.brazelog$default(r6, r7, r8, r9, r10, r11, r12, r13)
            r0 = r6
            com.braze.Braze$Companion r1 = com.braze.Braze.Companion
            r1.enableMockNetworkRequestsAndDropEventsMode()
            goto L52
        L51:
            r0 = r6
        L52:
            com.braze.images.DefaultBrazeImageLoader r1 = new com.braze.images.DefaultBrazeImageLoader
            android.content.Context r2 = r7.applicationContext
            r1.<init>(r2)
            r14.setImageLoader(r1)
            com.braze.events.e r1 = com.braze.Braze.staticExternalIEventMessenger
            r2 = 0
            if (r1 != 0) goto L6d
            com.braze.events.d r1 = new com.braze.events.d
            com.braze.storage.a0 r3 = new com.braze.storage.a0
            android.content.Context r6 = r7.applicationContext
            r3.<init>(r6)
            r1.<init>(r3, r2)
        L6d:
            r7.externalIEventMessenger = r1
            com.braze.A r1 = new com.braze.A
            r3 = 18
            r1.<init>(r3)
            androidx.navigation.compose.j r3 = new androidx.navigation.compose.j
            r6 = 2
            r3.<init>(r6, r14, r15)
            r14.run$android_sdk_base_release(r1, r2, r2, r3)
            long r2 = java.lang.System.nanoTime()
            com.braze.E r1 = new com.braze.E
            r6 = 0
            r1.<init>(r2, r4, r6)
            r9 = 0
            r10 = 0
            r8 = 0
            r12 = 7
            r13 = 0
            r6 = r0
            r11 = r1
            com.braze.support.BrazeLogger.brazelog$default(r6, r7, r8, r9, r10, r11, r12, r13)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.braze.Braze.<init>(android.content.Context):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _get_cachedContentCardsUpdatedEvent_$lambda$37() {
        return "Failed to retrieve the cached ContentCardsUpdatedEvent.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$0() {
        return "Braze SDK Initializing";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit _init_$lambda$27(Braze braze, Context context) {
        Braze braze2;
        Context context2;
        com.braze.configuration.e eVar;
        Braze braze3;
        braze.applyPendingRuntimeConfiguration$android_sdk_base_release();
        braze.setConfigurationProvider$android_sdk_base_release(new BrazeConfigurationProvider(braze.applicationContext));
        Companion companion = Companion;
        String configuredApiKey = companion.getConfiguredApiKey(braze.getConfigurationProvider$android_sdk_base_release());
        braze.isApiKeyPresent = Boolean.valueOf(!(configuredApiKey == null || StringsKt.O(configuredApiKey)));
        BrazeLogger.setInitialLogLevelFromConfiguration(braze.getConfigurationProvider$android_sdk_base_release().getLoggerInitialLogLevel());
        BrazeLogger.checkForSystemLogLevelProperty$default(false, 1, null);
        if (companion.getSdkEnablementProvider(context).a.getBoolean("appboy_sdk_disabled", false)) {
            companion.setOutboundNetworkRequestsOffline(true);
        }
        String str = braze.getConfigurationProvider$android_sdk_base_release().getBrazeApiKey().a;
        braze.setPushDeliveryManager$android_sdk_base_release(new com.braze.managers.i0(braze.applicationContext, str));
        braze.setDeviceIdProvider$android_sdk_base_release(new C1507u(braze.applicationContext, str));
        braze.offlineUserStorageProvider = new com.braze.configuration.e(braze.applicationContext);
        braze.setRegistrationDataProvider$android_sdk_base_release(new com.braze.managers.l0(braze.applicationContext, braze.getConfigurationProvider$android_sdk_base_release()));
        String customEndpoint = braze.getConfigurationProvider$android_sdk_base_release().getCustomEndpoint();
        if (customEndpoint != null && !StringsKt.O(customEndpoint)) {
            if (ValidationUtils.isInvalidCustomEndpoint$android_sdk_base_release(braze.getConfigurationProvider$android_sdk_base_release().getCustomEndpoint())) {
                BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
                BrazeLogger.Priority priority = BrazeLogger.Priority.W;
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(6), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(19), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(22), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(23), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(24), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(25), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(26), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(27), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(28), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(29), 6, (Object) null);
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new A(8), 6, (Object) null);
            }
            companion.setConfiguredCustomEndpoint$android_sdk_base_release(braze.getConfigurationProvider$android_sdk_base_release().getCustomEndpoint());
        }
        try {
            if (braze.getConfigurationProvider$android_sdk_base_release().isFirebaseCloudMessagingRegistrationEnabled()) {
                com.braze.managers.b0 b0Var = new com.braze.managers.b0(context, braze.getRegistrationDataProvider$android_sdk_base_release());
                if (b0Var.a()) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(9), 6, (Object) null);
                    String firebaseCloudMessagingSenderIdKey = braze.getConfigurationProvider$android_sdk_base_release().getFirebaseCloudMessagingSenderIdKey();
                    if (firebaseCloudMessagingSenderIdKey != null) {
                        b0Var.a(firebaseCloudMessagingSenderIdKey);
                    }
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new A(10), 6, (Object) null);
                }
                braze3 = braze;
            } else {
                braze3 = braze;
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze3, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(11), 6, (Object) null);
            }
            if (braze3.getConfigurationProvider$android_sdk_base_release().isAdmMessagingRegistrationEnabled()) {
                C1488a c1488a = C1489b.c;
                Context context3 = braze3.applicationContext;
                Intrinsics.checkNotNullParameter(context3, "context");
                if (c1488a.a() && c1488a.a(context3)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze3, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(12), 6, (Object) null);
                    new C1489b(braze3.applicationContext, braze3.getRegistrationDataProvider$android_sdk_base_release()).a();
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze3, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new A(13), 6, (Object) null);
                }
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(14), 6, (Object) null);
            }
            braze.verifyProperSdkSetup();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new A(15), 4, (Object) null);
        }
        BrazeLogger brazeLogger2 = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority2 = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger2, (Object) braze, priority2, (Throwable) null, false, (Function0) new A(16), 6, (Object) null);
        try {
            context2 = braze.applicationContext;
            eVar = braze.offlineUserStorageProvider;
        } catch (Exception e2) {
            braze2 = braze;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze2, BrazeLogger.Priority.E, (Throwable) e2, false, (Function0) new A(20), 4, (Object) null);
            braze2.publishError(e2);
        }
        if (eVar == null) {
            Intrinsics.m("offlineUserStorageProvider");
            throw null;
        }
        braze.setUserSpecificMemberVariablesAndStartDispatch(new u0(context2, eVar, braze.getConfigurationProvider$android_sdk_base_release(), braze.externalIEventMessenger, braze.getDeviceIdProvider$android_sdk_base_release(), braze.getRegistrationDataProvider$android_sdk_base_release(), braze.getPushDeliveryManager$android_sdk_base_release(), shouldMockNetworkRequestsAndDropEvents, areOutboundNetworkRequestsOffline, braze.getDeviceDataProvider(), shouldRequestFrameworkListenToNetworkUpdates));
        BrazeLogger.brazelog$default(brazeLogger2, (Object) braze, priority2, (Throwable) null, false, (Function0) new A(17), 6, (Object) null);
        braze2 = braze;
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze2, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new A(21), 6, (Object) null);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$28(long j, long j2) {
        StringBuilder sb = new StringBuilder("Braze SDK loaded in ");
        long j3 = j - j2;
        sb.append(TimeUnit.MILLISECONDS.convert(j3, TimeUnit.NANOSECONDS));
        sb.append(" ms / ");
        sb.append(j3);
        sb.append(" nanos");
        return sb.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _init_$lambda$3() {
        return "Failed to perform initial Braze singleton setup.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_registeredPushToken_$lambda$32(String str) {
        return AbstractC1484j.a("Failed to set the push token ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit _set_registeredPushToken_$lambda$36(Braze braze, String str) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.I;
        BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 7), 6, (Object) null);
        if (str == null || StringsKt.O(str)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(20), 6, (Object) null);
            return Unit.a;
        }
        if (Intrinsics.b(((com.braze.managers.l0) braze.getRegistrationDataProvider$android_sdk_base_release()).b(), str)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 8), 6, (Object) null);
            return Unit.a;
        }
        ((com.braze.managers.l0) braze.getRegistrationDataProvider$android_sdk_base_release()).a(str);
        com.braze.storage.r rVar = ((u0) braze.getUdm$android_sdk_base_release()).k;
        if (rVar == null) {
            Intrinsics.m("deviceCache");
            throw null;
        }
        rVar.e();
        braze.requestImmediateDataFlush();
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_registeredPushToken_$lambda$36$lambda$33(String str) {
        return AbstractC1484j.a("Push token registered: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_registeredPushToken_$lambda$36$lambda$34() {
        return "Push token must not be null or blank. Not registering for push with Braze.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String _set_registeredPushToken_$lambda$36$lambda$35(String str) {
        return AbstractC1475a.a("Push token ", str, " is the same as the previous token. Not calling sendFullDeviceObjectOnNextExport or requesting data flush");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addSerializedCardJsonToStorage$lambda$178(String str, String str2) {
        return android.support.v4.media.session.a.m("Failed to update ContentCard storage provider with single card update. User id: ", str, " Serialized json: ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit addSerializedCardJsonToStorage$lambda$180(String str, Braze braze, String str2) {
        if (StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1481g(2, str2, str), 6, (Object) null);
            return Unit.a;
        }
        ((u0) braze.getUdm$android_sdk_base_release()).C.a(new com.braze.models.response.c(str), str2);
        ((com.braze.events.d) braze.externalIEventMessenger).b(((u0) braze.getUdm$android_sdk_base_release()).C.a(true), ContentCardsUpdatedEvent.class);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addSerializedCardJsonToStorage$lambda$180$lambda$179(String str, String str2) {
        return android.support.v4.media.session.a.m("Cannot add null or blank card json to storage. Returning. User id: ", str, " Serialized json: ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addSingleSynchronousSubscription$lambda$125(Class cls) {
        return androidx.compose.ui.node.B.d(cls, "Failed to add synchronous subscriber for class: ");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String applyPendingRuntimeConfiguration$lambda$195$lambda$192() {
        return "Applying any pending runtime configuration values";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String applyPendingRuntimeConfiguration$lambda$195$lambda$193() {
        return "Clearing config values";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String applyPendingRuntimeConfiguration$lambda$195$lambda$194(BrazeConfig brazeConfig) {
        return "Setting pending config object: " + brazeConfig;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$130(String str) {
        return AbstractC1484j.a("Failed to set external id to: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit changeUser$lambda$138(String str, Braze braze, String str2) {
        Braze braze2;
        if (str == null || str.length() == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(15), 6, (Object) null);
            return Unit.a;
        }
        if (StringUtils.getByteSize(str) > 997) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 1), 6, (Object) null);
            return Unit.a;
        }
        BrazeUser brazeUser = braze.brazeUser;
        if (brazeUser == null) {
            Intrinsics.m("brazeUser");
            throw null;
        }
        String userId = brazeUser.getUserId();
        if (Intrinsics.b(userId, str)) {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 2), 6, (Object) null);
            if (str2 != null && !StringsKt.O(str2)) {
                BrazeLogger.brazelog$default(brazeLogger, (Object) braze, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str2, 3), 7, (Object) null);
                ((u0) braze.getUdm$android_sdk_base_release()).t.b(str2);
            }
        } else {
            com.braze.events.d dVar = ((u0) braze.getUdm$android_sdk_base_release()).l;
            ReentrantLock reentrantLock = dVar.g;
            reentrantLock.lock();
            try {
                reentrantLock.unlock();
                ((u0) braze.getUdm$android_sdk_base_release()).s.a();
                if (Intrinsics.b(userId, "")) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 4), 6, (Object) null);
                    com.braze.configuration.e eVar = braze.offlineUserStorageProvider;
                    if (eVar == null) {
                        Intrinsics.m("offlineUserStorageProvider");
                        throw null;
                    }
                    eVar.b(str);
                    BrazeUser brazeUser2 = braze.brazeUser;
                    if (brazeUser2 == null) {
                        Intrinsics.m("brazeUser");
                        throw null;
                    }
                    brazeUser2.setUserId(str);
                    braze2 = braze;
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C1481g(1, userId, str), 6, (Object) null);
                    braze2 = braze;
                    ((com.braze.events.d) braze2.externalIEventMessenger).b(new FeedUpdatedEvent(new ArrayList(), str, false, DateTimeUtils.nowInSeconds()), FeedUpdatedEvent.class);
                }
                ((u0) braze2.getUdm$android_sdk_base_release()).w.f();
                ((u0) braze2.getUdm$android_sdk_base_release()).n.a();
                com.braze.configuration.e eVar2 = braze2.offlineUserStorageProvider;
                if (eVar2 == null) {
                    Intrinsics.m("offlineUserStorageProvider");
                    throw null;
                }
                eVar2.b(str);
                com.braze.managers.h0 udm$android_sdk_base_release = braze2.getUdm$android_sdk_base_release();
                Context context = braze2.applicationContext;
                com.braze.configuration.e eVar3 = braze2.offlineUserStorageProvider;
                if (eVar3 == null) {
                    Intrinsics.m("offlineUserStorageProvider");
                    throw null;
                }
                braze2.setUserSpecificMemberVariablesAndStartDispatch(new u0(context, eVar3, braze2.getConfigurationProvider$android_sdk_base_release(), braze2.externalIEventMessenger, braze2.getDeviceIdProvider$android_sdk_base_release(), braze2.getRegistrationDataProvider$android_sdk_base_release(), braze2.getPushDeliveryManager$android_sdk_base_release(), shouldMockNetworkRequestsAndDropEvents, areOutboundNetworkRequestsOffline, braze2.getDeviceDataProvider(), shouldRequestFrameworkListenToNetworkUpdates));
                if (str2 != null && !StringsKt.O(str2)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str2, 5), 7, (Object) null);
                    ((u0) braze.getUdm$android_sdk_base_release()).t.b(str2);
                }
                ((u0) braze.getUdm$android_sdk_base_release()).a().j();
                ((u0) braze.getUdm$android_sdk_base_release()).w.o();
                u0 u0Var = (u0) udm$android_sdk_base_release;
                u0Var.getClass();
                kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new t0(u0Var, null), 3);
            } catch (Throwable th) {
                reentrantLock.unlock();
                throw th;
            }
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$131() {
        return "userId passed to changeUser was null or empty. The current user will remain the active user.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$132(String str) {
        return AbstractC1484j.a("Rejected user id with byte length longer than 997. Not changing user. Input user id: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$133(String str) {
        return AbstractC1475a.a("Received request to change current user ", str, " to the same user id. Not changing user.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$134(String str) {
        return AbstractC1484j.a("Set sdk auth signature on changeUser call: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$135(String str) {
        return AbstractC1484j.a("Changing anonymous user to ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$136(String str, String str2) {
        return "Changing current user " + str + " to new user " + str2 + '.';
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String changeUser$lambda$138$lambda$137(String str) {
        return AbstractC1484j.a("Set sdk auth signature on changeUser call: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String closeSession$lambda$41() {
        return "Failed to close session.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit closeSession$lambda$43(Activity activity, Braze braze) {
        if (activity == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new A(1), 6, (Object) null);
            return Unit.a;
        }
        ((u0) braze.getUdm$android_sdk_base_release()).w.a(activity);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String closeSession$lambda$43$lambda$42() {
        return "Cannot close session with null activity.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getCachedContentCards$lambda$144() {
        return "The ContentCardsUpdatedEvent was null. Returning null for the list of cached cards.";
    }

    private final ContentCardsUpdatedEvent getCachedContentCardsUpdatedEvent() {
        return (ContentCardsUpdatedEvent) runForResult$android_sdk_base_release$default(this, null, new androidx.lifecycle.compose.f(26), false, false, new C1478d(this, null), 12, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getConfigurationProviderSafe$lambda$221() {
        return "ConfigurationProvider has not been initialized. Constructing a new one.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String getCurrentUser$lambda$139() {
        return "Failed to retrieve the current user.";
    }

    private final com.braze.managers.d0 getDeviceDataProvider() {
        com.braze.managers.d0 c1506t = deviceDataProvider;
        if (c1506t == null) {
            c1506t = new C1506t(this.applicationContext, getConfigurationProvider$android_sdk_base_release());
        }
        deviceDataProvider = c1506t;
        return c1506t;
    }

    public static final Braze getInstance(Context context) {
        return Companion.getInstance(context);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleInAppMessageTestPush$lambda$188() {
        return "Error handling test in-app message push";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleInAppMessageTestPush$lambda$189(Intent intent, Braze braze) {
        Companion.requestTriggersIfInAppMessageTestPush$android_sdk_base_release(intent, ((u0) braze.getUdm$android_sdk_base_release()).w);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleInternalBannerRefresh$lambda$190() {
        return "Error handling banner push refresh";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit handleInternalBannerRefresh$lambda$191(Braze braze) {
        ((u0) braze.getUdm$android_sdk_base_release()).A.a(true);
        return Unit.a;
    }

    private final boolean isEphemeralEventKey(String str) {
        if (!getConfigurationProvider$android_sdk_base_release().isEphemeralEventsEnabled()) {
            return false;
        }
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(21), 6, (Object) null);
        Set<String> ephemeralEventKeys = getConfigurationProvider$android_sdk_base_release().getEphemeralEventKeys();
        boolean zContains = ephemeralEventKeys.contains(str);
        BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, (Function0) new r(str, ephemeralEventKeys, zContains, 0), 6, (Object) null);
        return zContains;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isEphemeralEventKey$lambda$217() {
        return "Ephemeral events enabled";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isEphemeralEventKey$lambda$218(String str, Set set, boolean z) {
        return "Checking event key [" + str + "] against ephemeral event list " + set + " and got match?: " + z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$2$lambda$1(String str) {
        return AbstractC1484j.a("Device build model matches a known crawler. Enabling mock network request mode. Device it: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$10() {
        return "**                Replace \"rest\" with \"sdk\" in your configuration                    **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$11() {
        return "**                                        See                                        **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$12() {
        return "**  https://www.braze.com/docs/user_guide/administrative/access_braze/sdk_endpoints  **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$13() {
        return "**                                                                                   **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$14() {
        return "***************************************************************************************";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$15() {
        return "Firebase Cloud Messaging found. Setting up Firebase Cloud Messaging.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$17() {
        return "Firebase Cloud Messaging requirements not met. Braze will not register for Firebase Cloud Messaging.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$18() {
        return "Automatic Firebase Cloud Messaging registration not enabled in configuration. Braze will not register for Firebase Cloud Messaging.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$19() {
        return "Amazon Device Messaging found. Setting up Amazon Device Messaging";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$20() {
        return "ADM manifest requirements not met. Braze will not register for ADM.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$21() {
        return "Automatic ADM registration not enabled in configuration. Braze will not register for ADM.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$22() {
        return "Failed to setup pre SDK tasks";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$23() {
        return "Starting up a new user dependency manager";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$24() {
        return "Finished UserDependencyManager creation.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$25() {
        return "Failed to startup user dependency manager.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$26() {
        return "Finished singleton setup.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$4() {
        return "***************************************************************************************";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$5() {
        return "**                                                                                   **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$6() {
        return "**                                   !! WARNING !!                                   **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$7() {
        return "**                                                                                   **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$8() {
        return "**                       You are using a Braze REST API endpoint                     **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String lambda$27$lambda$9() {
        return "**                             instead of an SDK endpoint                            **";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$44(String str) {
        return AbstractC1484j.a("Failed to log custom event: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logCustomEvent$lambda$50(Braze braze, String str, BrazeProperties brazeProperties, BrazeProperties brazeProperties2) {
        BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
        BrazeLogger.Priority priority = BrazeLogger.Priority.V;
        BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new C1479e(str, brazeProperties2, 1), 6, (Object) null);
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = str;
        if (!ValidationUtils.isValidLogCustomEventInput(str, ((u0) braze.getUdm$android_sdk_base_release()).m)) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1480f(j, 1), 6, (Object) null);
            return Unit.a;
        }
        if (brazeProperties != null && brazeProperties.isInvalid()) {
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1480f(j, 2), 6, (Object) null);
            return Unit.a;
        }
        String strEnsureBrazeFieldLength = ValidationUtils.ensureBrazeFieldLength((String) j.a);
        j.a = strEnsureBrazeFieldLength;
        com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a(strEnsureBrazeFieldLength, brazeProperties);
        if (iVarA == null) {
            return Unit.a;
        }
        BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new C1479e(str, brazeProperties2, 0), 6, (Object) null);
        if (braze.isEphemeralEventKey((String) j.a) ? ((u0) braze.getUdm$android_sdk_base_release()).m.F() : ((u0) braze.getUdm$android_sdk_base_release()).w.a(iVarA)) {
            ((u0) braze.getUdm$android_sdk_base_release()).F.a((com.braze.triggers.events.i) new com.braze.triggers.events.a((String) j.a, brazeProperties, iVarA));
        } else {
            BrazeLogger.brazelog$default(brazeLogger, (Object) braze, priority, (Throwable) null, false, (Function0) new C1480f(j, 0), 6, (Object) null);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$50$lambda$45(String str, BrazeProperties brazeProperties) {
        return "Called logCustomEvent for custom event " + str + " and properties " + brazeProperties;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$50$lambda$46(kotlin.jvm.internal.J j) {
        return AbstractC1477c.a(new StringBuilder("Logged custom event with name "), (String) j.a, " was invalid. Not logging custom event to Braze.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$50$lambda$47(kotlin.jvm.internal.J j) {
        return AbstractC1477c.a(new StringBuilder("Custom event with name "), (String) j.a, " logged with invalid properties. Not logging custom event to Braze.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$50$lambda$48(String str, BrazeProperties brazeProperties) {
        return "Logging custom event " + str + " and properties " + brazeProperties;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logCustomEvent$lambda$50$lambda$49(kotlin.jvm.internal.J j) {
        return AbstractC1477c.a(new StringBuilder("Not passing event with name "), (String) j.a, " to trigger manager");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logFeedDisplayed$lambda$72() {
        return "Failed to log that the feed was displayed.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logFeedDisplayed$lambda$74(Braze braze) {
        com.braze.models.i iVarA = com.braze.models.outgoing.event.b.g.a();
        if (iVarA != null) {
            ((u0) braze.getUdm$android_sdk_base_release()).w.a(iVarA);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPurchase$lambda$51(String str) {
        return AbstractC1484j.a("Failed to log purchase event of: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPurchase$lambda$54(String str, String str2, BigDecimal bigDecimal, int i, Braze braze, BrazeProperties brazeProperties) {
        if (!ValidationUtils.isValidLogPurchaseInput(str, str2, bigDecimal, i, ((u0) braze.getUdm$android_sdk_base_release()).m)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(22), 6, (Object) null);
            return Unit.a;
        }
        if (brazeProperties != null && brazeProperties.isInvalid()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(23), 6, (Object) null);
            return Unit.a;
        }
        String strEnsureBrazeFieldLength = ValidationUtils.ensureBrazeFieldLength(str);
        com.braze.models.outgoing.event.a aVar = com.braze.models.outgoing.event.b.g;
        Intrinsics.d(str2);
        Intrinsics.d(bigDecimal);
        com.braze.models.i iVarA = aVar.a(strEnsureBrazeFieldLength, str2, bigDecimal, i, brazeProperties);
        if (iVarA == null) {
            return Unit.a;
        }
        if (((u0) braze.getUdm$android_sdk_base_release()).w.a(iVarA)) {
            ((u0) braze.getUdm$android_sdk_base_release()).F.a((com.braze.triggers.events.i) new com.braze.triggers.events.f(strEnsureBrazeFieldLength, brazeProperties, iVarA));
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPurchase$lambda$54$lambda$52() {
        return "Log purchase input was invalid. Not logging in-app purchase to Braze.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPurchase$lambda$54$lambda$53() {
        return "Purchase logged with invalid properties. Not logging custom event to Braze.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushDelivery$lambda$200(String str) {
        return AbstractC1484j.a("Error logging Push Delivery ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPushDelivery$lambda$201(Braze braze, String str, long j) {
        ((u0) braze.getUdm$android_sdk_base_release()).w.a(str);
        braze.schedulePushDelivery$android_sdk_base_release(j);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushMaxCampaign$lambda$206() {
        return "Failed to log push max campaign";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPushMaxCampaign$lambda$207(Braze braze, String str) {
        ((u0) braze.getUdm$android_sdk_base_release()).w.c(str);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationActionClicked$lambda$63() {
        return "Failed to log push notification action clicked.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPushNotificationActionClicked$lambda$67(String campaignId, Braze braze, String actionId, String actionType) throws JSONException {
        if (campaignId == null || StringsKt.O(campaignId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(14), 6, (Object) null);
            return Unit.a;
        }
        if (actionId == null || StringsKt.O(actionId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(13), 6, (Object) null);
            return Unit.a;
        }
        if (actionType == null || StringsKt.O(actionType)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(12), 6, (Object) null);
            return Unit.a;
        }
        C1500m c1500m = ((u0) braze.getUdm$android_sdk_base_release()).w;
        int i = com.braze.models.outgoing.event.push.a.j;
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        Intrinsics.checkNotNullParameter(actionId, "actionId");
        Intrinsics.checkNotNullParameter(actionType, "actionType");
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("cid", campaignId);
        jSONObject.put("a", actionId);
        com.braze.enums.d dVar = com.braze.enums.e.b;
        c1500m.a(new com.braze.models.outgoing.event.push.a(jSONObject, actionType));
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationActionClicked$lambda$67$lambda$64() {
        return "No campaign Id associated with this notification (this is expected for test sends). Not logging push notification action clicked.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationActionClicked$lambda$67$lambda$65() {
        return "Action ID cannot be null or blank.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationActionClicked$lambda$67$lambda$66() {
        return "Action Type cannot be null or blank.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationOpened$lambda$58(Intent intent) {
        return "Error logging push notification with intent: " + intent;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPushNotificationOpened$lambda$62(Intent intent, Braze braze) throws JSONException {
        if (intent == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C(16), 6, (Object) null);
            return Unit.a;
        }
        String campaignId = intent.getStringExtra("cid");
        if (campaignId == null || StringsKt.O(campaignId)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new C(17), 6, (Object) null);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(campaignId, 14), 6, (Object) null);
            C1500m c1500m = ((u0) braze.getUdm$android_sdk_base_release()).w;
            int i = com.braze.models.outgoing.event.push.b.j;
            Intrinsics.checkNotNullParameter(campaignId, "campaignId");
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("cid", campaignId);
            com.braze.enums.d dVar = com.braze.enums.e.b;
            c1500m.a(new com.braze.models.outgoing.event.push.b(jSONObject));
        }
        Companion.requestTriggersIfInAppMessageTestPush$android_sdk_base_release(intent, ((u0) braze.getUdm$android_sdk_base_release()).w);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationOpened$lambda$62$lambda$59() {
        return "Cannot logPushNotificationOpened with null intent. Not logging push click.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationOpened$lambda$62$lambda$60(String str) {
        return AbstractC1484j.a("Logging push click. Campaign Id: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushNotificationOpened$lambda$62$lambda$61() {
        return "No campaign Id associated with this notification (this is expected for test sends). Not logging push click.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushStoryPageClicked$lambda$68(String str, String str2) {
        return android.support.v4.media.session.a.m("Failed to log push story page clicked for pageId: ", str, " campaignId: ", str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit logPushStoryPageClicked$lambda$71(String str, String str2, Braze braze) {
        if (!ValidationUtils.isValidPushStoryClickInput(str, str2)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(19), 6, (Object) null);
            return Unit.a;
        }
        com.braze.models.outgoing.event.a aVar = com.braze.models.outgoing.event.b.g;
        Intrinsics.d(str);
        Intrinsics.d(str2);
        com.braze.models.i iVarO = aVar.o(str, str2);
        if (iVarO != null) {
            ((u0) braze.getUdm$android_sdk_base_release()).w.a(iVarO);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String logPushStoryPageClicked$lambda$71$lambda$69() {
        return "Push story page click input was invalid. Not logging in-app purchase to Braze.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String openSession$lambda$38() {
        return "Failed to open session.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit openSession$lambda$40(Activity activity, Braze braze) {
        if (activity == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new A(3), 6, (Object) null);
            return Unit.a;
        }
        ((u0) braze.getUdm$android_sdk_base_release()).w.c(activity);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String openSession$lambda$40$lambda$39() {
        return "Cannot open session with null activity.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String performPushDeliveryFlush$lambda$204() {
        return "Failed to flush push delivery events";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit performPushDeliveryFlush$lambda$205(Braze braze) {
        ((u0) braze.getUdm$android_sdk_base_release()).w.a(0L);
        return Unit.a;
    }

    private final void publishError(Throwable th) {
        if (this.udm == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, th, false, (Function0) new A(4), 4, (Object) null);
            return;
        }
        try {
            ((u0) getUdm$android_sdk_base_release()).l.b(th, Throwable.class);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(0, th), 4, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String publishError$lambda$212() {
        return "User dependency manager is uninitialized. Not publishing error.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String publishError$lambda$213(Throwable th) {
        return "Failed to log throwable: " + th;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String reenqueueInAppMessage$lambda$198(InAppMessageEvent inAppMessageEvent) {
        return "Error reenqueueing In-App Message from event " + inAppMessageEvent;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit reenqueueInAppMessage$lambda$199(Braze braze, InAppMessageEvent inAppMessageEvent) {
        ((u0) braze.getUdm$android_sdk_base_release()).F.b(inAppMessageEvent.getTriggerAction());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String refreshFeatureFlags$lambda$84() {
        return "Failed to refresh feature flags.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit refreshFeatureFlags$lambda$86(Braze braze) {
        if (((u0) braze.getUdm$android_sdk_base_release()).m.G()) {
            ((u0) braze.getUdm$android_sdk_base_release()).z.f();
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(24), 6, (Object) null);
            ((u0) braze.getUdm$android_sdk_base_release()).l.b(new com.braze.events.internal.j(), com.braze.events.internal.j.class);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String refreshFeatureFlags$lambda$86$lambda$85() {
        return "Feature flags not enabled. Not refreshing feature flags.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeSingleSubscription$lambda$128$lambda$126(Class cls, IEventSubscriber iEventSubscriber, boolean z) {
        return "Did remove the background " + cls + ' ' + iEventSubscriber + "? " + z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeSingleSubscription$lambda$128$lambda$127(Class cls, IEventSubscriber iEventSubscriber, boolean z) {
        return "Did remove the synchronous " + cls + ' ' + iEventSubscriber + "? " + z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String removeSingleSubscription$lambda$129(Class cls) {
        return assistantMode.refactored.a.i(cls, new StringBuilder("Failed to remove "), " subscriber.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestContentCardsRefresh$lambda$79() {
        return "Failed to request Content Cards refresh from Braze servers.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestContentCardsRefresh$lambda$81(Braze braze) {
        if (((u0) braze.getUdm$android_sdk_base_release()).m.D()) {
            ((u0) braze.getUdm$android_sdk_base_release()).w.a(((u0) braze.getUdm$android_sdk_base_release()).C.c, ((u0) braze.getUdm$android_sdk_base_release()).C.d, 0);
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(2), 7, (Object) null);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestContentCardsRefresh$lambda$81$lambda$80() {
        return "Content Cards is not enabled, skipping API call to refresh";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestContentCardsRefreshFromCache$lambda$82() {
        return "Failed to request Content Cards refresh from the cache.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestContentCardsRefreshFromCache$lambda$83(Braze braze) {
        ((com.braze.events.d) braze.externalIEventMessenger).b(((u0) braze.getUdm$android_sdk_base_release()).C.a(true), ContentCardsUpdatedEvent.class);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestFeedRefresh$lambda$77() {
        return "Failed to request refresh of feed.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestFeedRefresh$lambda$78(Braze braze) {
        C1500m c1500m = ((u0) braze.getUdm$android_sdk_base_release()).w;
        com.braze.models.outgoing.j jVar = new com.braze.models.outgoing.j();
        jVar.b = Boolean.TRUE;
        c1500m.a(jVar);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestFeedRefreshFromCache$lambda$75() {
        return "Failed to retrieve and publish feed from offline cache.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestFeedRefreshFromCache$lambda$76(Braze braze) {
        com.braze.events.e eVar = braze.externalIEventMessenger;
        com.braze.storage.x xVar = ((u0) braze.getUdm$android_sdk_base_release()).B;
        com.braze.events.d dVar = (com.braze.events.d) eVar;
        dVar.b(xVar.a(new JSONArray(xVar.b.getString("cards", "[]")), xVar.b.getString("uid", ""), true, xVar.b.getLong("cards_timestamp", -1L)), FeedUpdatedEvent.class);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestGeofenceRefresh$lambda$176(boolean z) {
        return "Failed to request geofence refresh with rate limit ignore: " + z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestGeofenceRefresh$lambda$177(Braze braze, boolean z) {
        ((u0) braze.getUdm$android_sdk_base_release()).x.requestGeofenceRefresh(z);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestImmediateDataFlush$lambda$105() {
        return "Failed to request data flush.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit requestImmediateDataFlush$lambda$107(Braze braze) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(18), 6, (Object) null);
        C1500m c1500m = ((u0) braze.getUdm$android_sdk_base_release()).w;
        c1500m.getClass();
        c1500m.a(new com.braze.models.outgoing.j());
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String requestImmediateDataFlush$lambda$107$lambda$106() {
        return "requestImmediateDataFlush() called";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String retryInAppMessage$lambda$196(InAppMessageEvent inAppMessageEvent) {
        return "Error retrying In-App Message from event " + inAppMessageEvent;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit retryInAppMessage$lambda$197(Braze braze, InAppMessageEvent inAppMessageEvent) {
        ((u0) braze.getUdm$android_sdk_base_release()).F.a(inAppMessageEvent.getTriggerEvent(), inAppMessageEvent.getTriggerAction());
        return Unit.a;
    }

    public static /* synthetic */ void run$android_sdk_base_release$default(Braze braze, Function0 function0, boolean z, boolean z2, Function0 function02, int i, Object obj) {
        if ((i & 2) != 0) {
            z = true;
        }
        if ((i & 4) != 0) {
            z2 = true;
        }
        braze.run$android_sdk_base_release(function0, z, z2, function02);
    }

    public static /* synthetic */ Object runForResult$android_sdk_base_release$default(Braze braze, Object obj, Function0 function0, boolean z, boolean z2, Function2 function2, int i, Object obj2) {
        if ((i & 4) != 0) {
            z = true;
        }
        if ((i & 8) != 0) {
            z2 = true;
        }
        return braze.runForResult$android_sdk_base_release(obj, function0, z, z2, function2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String schedulePushDelivery$lambda$202() {
        return "Error scheduling push delivery";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit schedulePushDelivery$lambda$203(Braze braze, long j) {
        ((u0) braze.getUdm$android_sdk_base_release()).w.a(j);
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void setSyncPolicyOfflineStatus(boolean z) {
        int i = 1;
        run$android_sdk_base_release$default(this, new C1483i(z, i), false, false, new C1485k(this, z, i), 6, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setSyncPolicyOfflineStatus$lambda$209(boolean z) {
        return "Failed to set sync policy offline to " + z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit setSyncPolicyOfflineStatus$lambda$211(Braze braze, boolean z) {
        ((u0) braze.getUdm$android_sdk_base_release()).w.getClass();
        com.braze.dispatch.f fVar = ((u0) braze.getUdm$android_sdk_base_release()).p;
        synchronized (fVar) {
            try {
                fVar.l = z;
                fVar.b();
                if (z) {
                    fVar.f();
                } else {
                    fVar.c();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (braze.imageLoader != null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1483i(z, 2), 7, (Object) null);
            braze.getImageLoader().setOffline(z);
        }
        return Unit.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String setSyncPolicyOfflineStatus$lambda$211$lambda$210(boolean z) {
        return "Setting the image loader deny network downloads to " + z;
    }

    private final void setUserSpecificMemberVariablesAndStartDispatch(u0 u0Var) {
        setUdm$android_sdk_base_release(u0Var);
        com.braze.coroutine.f fVar = com.braze.coroutine.f.a;
        com.braze.coroutine.f.b = ((u0) getUdm$android_sdk_base_release()).l;
        com.braze.storage.h0 h0VarA = ((u0) getUdm$android_sdk_base_release()).a();
        C1500m c1500m = ((u0) getUdm$android_sdk_base_release()).w;
        com.braze.configuration.e eVar = this.offlineUserStorageProvider;
        if (eVar == null) {
            Intrinsics.m("offlineUserStorageProvider");
            throw null;
        }
        this.brazeUser = new BrazeUser(h0VarA, c1500m, eVar.a(), ((u0) getUdm$android_sdk_base_release()).y, ((u0) getUdm$android_sdk_base_release()).m);
        ((u0) getUdm$android_sdk_base_release()).o.a(((u0) getUdm$android_sdk_base_release()).l);
        ((u0) getUdm$android_sdk_base_release()).l.a();
        ((u0) getUdm$android_sdk_base_release()).r.a(((u0) getUdm$android_sdk_base_release()).l);
        ((u0) getUdm$android_sdk_base_release()).E.g();
        com.braze.events.e eVar2 = this.externalIEventMessenger;
        BrazeUser brazeUser = this.brazeUser;
        if (brazeUser == null) {
            Intrinsics.m("brazeUser");
            throw null;
        }
        ((com.braze.events.d) eVar2).b(new BrazeUserChangeEvent(brazeUser.getUserId()), BrazeUserChangeEvent.class);
        com.braze.events.d dVar = ((u0) getUdm$android_sdk_base_release()).l;
        BrazeUser brazeUser2 = this.brazeUser;
        if (brazeUser2 != null) {
            dVar.b(new BrazeUserChangeEvent(brazeUser2.getUserId()), BrazeUserChangeEvent.class);
        } else {
            Intrinsics.m("brazeUser");
            throw null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String subscribeToContentCardsUpdates$lambda$110() {
        return "Failed to add subscriber for Content Cards updates.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String subscribeToFeedUpdates$lambda$120() {
        return "Failed to add subscriber for feed updates.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String subscribeToNewInAppMessages$lambda$108() {
        return "Failed to add subscriber to new in-app messages.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String validateAndStorePushId$lambda$208() {
        return "Failed to validate and store push identifier";
    }

    private final void verifyProperSdkSetup() {
        boolean z = true;
        for (String str : NECESSARY_BRAZE_SDK_PERMISSIONS) {
            if (!PermissionUtils.hasPermission(this.applicationContext, str)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new androidx.navigation.internal.l(str, 9), 6, (Object) null);
                z = false;
            }
        }
        if (StringsKt.O(getConfigurationProvider$android_sdk_base_release().getBrazeApiKey().a)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(6), 6, (Object) null);
            z = false;
        }
        if (z) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(7), 6, (Object) null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String verifyProperSdkSetup$lambda$214(String str) {
        return AbstractC1475a.a("The Braze SDK requires the permission ", str, ". Check your AndroidManifest.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String verifyProperSdkSetup$lambda$215() {
        return "The Braze SDK requires a non-empty API key. Check your braze.xml or BrazeConfig.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String verifyProperSdkSetup$lambda$216() {
        return "The Braze SDK is not integrated correctly. Please visit https://www.braze.com/docs/developer_guide/platform_integration_guides/android/initial_sdk_setup/android_sdk_integration/";
    }

    public final /* synthetic */ void addSerializedCardJsonToStorage$android_sdk_base_release(String serializedCardJson, String str) {
        Intrinsics.checkNotNullParameter(serializedCardJson, "serializedCardJson");
        int i = 0;
        run$android_sdk_base_release$default(this, new C1481g(i, str, serializedCardJson), false, false, new C1482h(serializedCardJson, this, str, i), 6, null);
    }

    public <T> void addSingleSynchronousSubscription(IEventSubscriber<T> subscriber, Class<T> eventClass) {
        Intrinsics.checkNotNullParameter(subscriber, "subscriber");
        Intrinsics.checkNotNullParameter(eventClass, "eventClass");
        try {
            ((com.braze.events.d) this.externalIEventMessenger).c((Class) eventClass, (IEventSubscriber) subscriber);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new z(eventClass, 1), 4, (Object) null);
            publishError(e);
        }
    }

    public final /* synthetic */ void applyPendingRuntimeConfiguration$android_sdk_base_release() {
        ReentrantLock reentrantLock = brazeClassLock;
        reentrantLock.lock();
        try {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(4), 7, (Object) null);
            Braze braze = this;
            RuntimeAppConfigurationProvider runtimeAppConfigurationProvider = new RuntimeAppConfigurationProvider(braze.applicationContext);
            for (BrazeConfig brazeConfig : pendingConfigurations) {
                if (Intrinsics.b(brazeConfig, clearConfigSentinel)) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) braze, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new C(5), 6, (Object) null);
                    runtimeAppConfigurationProvider.clearAllConfigurationValues();
                } else {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(brazeConfig, 0), 6, (Object) null);
                    runtimeAppConfigurationProvider.setConfiguration(brazeConfig);
                }
                braze = this;
            }
            pendingConfigurations.clear();
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public void changeUser(String str) {
        changeUser(str, null);
    }

    public void closeSession(Activity activity) {
        run$android_sdk_base_release$default(this, new C(20), false, false, new C1508n(activity, this, 0), 6, null);
    }

    public List<Card> getCachedContentCards() {
        ContentCardsUpdatedEvent cachedContentCardsUpdatedEvent = getCachedContentCardsUpdatedEvent();
        if (cachedContentCardsUpdatedEvent != null) {
            return cachedContentCardsUpdatedEvent.getAllCards();
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new androidx.lifecycle.compose.f(25), 6, (Object) null);
        return null;
    }

    public final BrazeConfigurationProvider getConfigurationProvider$android_sdk_base_release() {
        BrazeConfigurationProvider brazeConfigurationProvider = this.configurationProvider;
        if (brazeConfigurationProvider != null) {
            return brazeConfigurationProvider;
        }
        Intrinsics.m("configurationProvider");
        throw null;
    }

    public final BrazeConfigurationProvider getConfigurationProviderSafe$android_sdk_base_release(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (this.configurationProvider != null) {
            return getConfigurationProvider$android_sdk_base_release();
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C(8), 7, (Object) null);
        return new BrazeConfigurationProvider(context);
    }

    public void getCurrentUser(IValueCallback<BrazeUser> completionCallback) {
        Intrinsics.checkNotNullParameter(completionCallback, "completionCallback");
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new C1487m(completionCallback, this, null), 3);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new C(15), 4, (Object) null);
            completionCallback.onError();
            publishError(e);
        }
    }

    public final com.braze.managers.e0 getDeviceIdProvider$android_sdk_base_release() {
        com.braze.managers.e0 e0Var = this.deviceIdProvider;
        if (e0Var != null) {
            return e0Var;
        }
        Intrinsics.m("deviceIdProvider");
        throw null;
    }

    public final com.braze.events.e getExternalIEventMessenger$android_sdk_base_release() {
        return this.externalIEventMessenger;
    }

    public IBrazeImageLoader getImageLoader() {
        IBrazeImageLoader iBrazeImageLoader = this.imageLoader;
        if (iBrazeImageLoader != null) {
            return iBrazeImageLoader;
        }
        Intrinsics.m("imageLoader");
        throw null;
    }

    public final com.braze.managers.i0 getPushDeliveryManager$android_sdk_base_release() {
        com.braze.managers.i0 i0Var = this.pushDeliveryManager;
        if (i0Var != null) {
            return i0Var;
        }
        Intrinsics.m("pushDeliveryManager");
        throw null;
    }

    public final com.braze.managers.g0 getRegistrationDataProvider$android_sdk_base_release() {
        com.braze.managers.g0 g0Var = this.registrationDataProvider;
        if (g0Var != null) {
            return g0Var;
        }
        Intrinsics.m("registrationDataProvider");
        throw null;
    }

    public final com.braze.managers.h0 getUdm$android_sdk_base_release() {
        com.braze.managers.h0 h0Var = this.udm;
        if (h0Var != null) {
            return h0Var;
        }
        Intrinsics.m("udm");
        throw null;
    }

    public final /* synthetic */ void handleInAppMessageTestPush$android_sdk_base_release(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        run$android_sdk_base_release$default(this, new C(9), false, false, new I(intent, this, 0), 6, null);
    }

    public final /* synthetic */ void handleInternalBannerRefresh$android_sdk_base_release() {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(16), false, false, new C1509o(this, 0), 6, null);
    }

    public final Boolean isApiKeyPresent$android_sdk_base_release() {
        return this.isApiKeyPresent;
    }

    public void logCustomEvent(String str, BrazeProperties brazeProperties) {
        run$android_sdk_base_release$default(this, new androidx.navigation.internal.l(str, 10), false, false, new androidx.work.impl.utils.o(this, str, brazeProperties != null ? brazeProperties.clone() : null, brazeProperties, 1), 6, null);
    }

    public void logFeedDisplayed() {
        run$android_sdk_base_release$default(this, new C(10), false, false, new C1509o(this, 8), 6, null);
    }

    public void logPurchase(String str, String str2, BigDecimal bigDecimal, int i, BrazeProperties brazeProperties) {
        run$android_sdk_base_release$default(this, new androidx.navigation.internal.l(str, 6), false, false, new C1511q(str, str2, bigDecimal, i, this, brazeProperties != null ? brazeProperties.clone() : null), 6, null);
    }

    public final /* synthetic */ void logPushDelivery$android_sdk_base_release(String campaignId, long j) {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        run$android_sdk_base_release$default(this, new androidx.navigation.internal.l(campaignId, 11), false, false, new H(this, campaignId, j, 0), 6, null);
    }

    public final /* synthetic */ void logPushMaxCampaign$android_sdk_base_release(String campaign) {
        Intrinsics.checkNotNullParameter(campaign, "campaign");
        run$android_sdk_base_release$default(this, new C(13), false, false, new K(this, campaign, 0), 6, null);
    }

    public void logPushNotificationActionClicked(String str, String str2, String str3) {
        run$android_sdk_base_release$default(this, new C(12), false, false, new androidx.work.impl.utils.o(str, this, str2, str3, 2), 6, null);
    }

    public void logPushNotificationOpened(Intent intent) {
        run$android_sdk_base_release$default(this, new J(0, intent), false, false, new I(intent, this, 1), 6, null);
    }

    public void logPushStoryPageClicked(String str, String str2) {
        run$android_sdk_base_release$default(this, new C1481g(3, str2, str), false, false, new C1482h(str, this, str2), 6, null);
    }

    public void openSession(Activity activity) {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(18), false, false, new C1508n(activity, this, 1), 6, null);
    }

    public final /* synthetic */ void performPushDeliveryFlush$android_sdk_base_release() {
        run$android_sdk_base_release$default(this, new C(1), false, false, new C1509o(this, 6), 6, null);
    }

    public final /* synthetic */ void publishBrazePushAction$android_sdk_base_release(BrazePushEventType pushActionType, BrazeNotificationPayload payload) {
        Intrinsics.checkNotNullParameter(pushActionType, "pushActionType");
        Intrinsics.checkNotNullParameter(payload, "payload");
        ((com.braze.events.d) this.externalIEventMessenger).b(new BrazePushEvent(pushActionType, payload), BrazePushEvent.class);
    }

    public final void reenqueueInAppMessage$android_sdk_base_release(InAppMessageEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        int i = 0;
        run$android_sdk_base_release$default(this, new F(event, i), false, false, new G(this, event, i), 6, null);
    }

    public void refreshFeatureFlags() {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(17), false, false, new C1509o(this, 1), 6, null);
    }

    public <T> void removeSingleSubscription(final IEventSubscriber<T> iEventSubscriber, final Class<T> eventClass) {
        Intrinsics.checkNotNullParameter(eventClass, "eventClass");
        if (iEventSubscriber != null) {
            try {
                final boolean zA = ((com.braze.events.d) this.externalIEventMessenger).a((Class) eventClass, (IEventSubscriber) iEventSubscriber);
                BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
                BrazeLogger.Priority priority = BrazeLogger.Priority.V;
                final int i = 0;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0() { // from class: com.braze.s
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i) {
                            case 0:
                                return Braze.removeSingleSubscription$lambda$128$lambda$126(eventClass, iEventSubscriber, zA);
                            default:
                                return Braze.removeSingleSubscription$lambda$128$lambda$127(eventClass, iEventSubscriber, zA);
                        }
                    }
                }, 6, (Object) null);
                final boolean zB = ((com.braze.events.d) this.externalIEventMessenger).b((Class) eventClass, (IEventSubscriber) iEventSubscriber);
                final int i2 = 1;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, false, new Function0() { // from class: com.braze.s
                    @Override // kotlin.jvm.functions.Function0
                    public final Object invoke() {
                        switch (i2) {
                            case 0:
                                return Braze.removeSingleSubscription$lambda$128$lambda$126(eventClass, iEventSubscriber, zB);
                            default:
                                return Braze.removeSingleSubscription$lambda$128$lambda$127(eventClass, iEventSubscriber, zB);
                        }
                    }
                }, 6, (Object) null);
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new z(eventClass, 0), 4, (Object) null);
                publishError(e);
            }
        }
    }

    @InterfaceC4935d
    public void requestContentCardsRefresh(boolean z) {
        if (z) {
            requestContentCardsRefreshFromCache();
        } else {
            requestContentCardsRefresh();
        }
    }

    public void requestContentCardsRefreshFromCache() {
        run$android_sdk_base_release$default(this, new C(0), false, false, new C1509o(this, 5), 6, null);
    }

    public void requestFeedRefresh() {
        run$android_sdk_base_release$default(this, new A(2), false, false, new C1509o(this, 4), 6, null);
    }

    public void requestFeedRefreshFromCache() {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(28), false, false, new C1509o(this, 3), 6, null);
    }

    public final /* synthetic */ void requestGeofenceRefresh$android_sdk_base_release(boolean z) {
        int i = 0;
        run$android_sdk_base_release$default(this, new C1483i(z, i), false, false, new C1485k(this, z, i), 6, null);
    }

    public void requestImmediateDataFlush() {
        run$android_sdk_base_release$default(this, new C(14), false, false, new C1509o(this, 7), 6, null);
    }

    public final /* synthetic */ void retryInAppMessage$android_sdk_base_release(InAppMessageEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        int i = 1;
        run$android_sdk_base_release$default(this, new F(event, i), false, false, new G(this, event, i), 6, null);
    }

    public final /* synthetic */ void run$android_sdk_base_release(Function0 errorLog, boolean z, boolean z2, Function0 block) {
        Intrinsics.checkNotNullParameter(errorLog, "errorLog");
        Intrinsics.checkNotNullParameter(block, "block");
        try {
            kotlinx.coroutines.E.A(com.braze.coroutine.f.a, null, null, new C1521u(z, z2, this, block, errorLog, null), 3);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, errorLog, 4, (Object) null);
            publishError(e);
        }
    }

    public final <T> T runForResult$android_sdk_base_release(T t, Function0<String> errorLog, boolean z, boolean z2, Function2<? super kotlinx.coroutines.C, ? super kotlin.coroutines.h<? super T>, ? extends Object> block) {
        Intrinsics.checkNotNullParameter(errorLog, "errorLog");
        Intrinsics.checkNotNullParameter(block, "block");
        try {
            return (T) kotlinx.coroutines.E.D(kotlin.coroutines.n.a, new C1531x(z, t, z2, this, block, errorLog, null));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) errorLog, 4, (Object) null);
            publishError(e);
            return t;
        }
    }

    public final /* synthetic */ void schedulePushDelivery$android_sdk_base_release(long j) {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(19), false, false, new C1510p(this, j, 0), 6, null);
    }

    public final void setConfigurationProvider$android_sdk_base_release(BrazeConfigurationProvider brazeConfigurationProvider) {
        Intrinsics.checkNotNullParameter(brazeConfigurationProvider, "<set-?>");
        this.configurationProvider = brazeConfigurationProvider;
    }

    public final void setDeviceIdProvider$android_sdk_base_release(com.braze.managers.e0 e0Var) {
        Intrinsics.checkNotNullParameter(e0Var, "<set-?>");
        this.deviceIdProvider = e0Var;
    }

    public void setImageLoader(IBrazeImageLoader iBrazeImageLoader) {
        Intrinsics.checkNotNullParameter(iBrazeImageLoader, "<set-?>");
        this.imageLoader = iBrazeImageLoader;
    }

    public final void setPushDeliveryManager$android_sdk_base_release(com.braze.managers.i0 i0Var) {
        Intrinsics.checkNotNullParameter(i0Var, "<set-?>");
        this.pushDeliveryManager = i0Var;
    }

    public void setRegisteredPushToken(String str) {
        run$android_sdk_base_release$default(this, new androidx.navigation.internal.l(str, 13), false, false, new K(this, str, 1), 6, null);
    }

    public final void setRegistrationDataProvider$android_sdk_base_release(com.braze.managers.g0 g0Var) {
        Intrinsics.checkNotNullParameter(g0Var, "<set-?>");
        this.registrationDataProvider = g0Var;
    }

    public final void setUdm$android_sdk_base_release(com.braze.managers.h0 h0Var) {
        Intrinsics.checkNotNullParameter(h0Var, "<set-?>");
        this.udm = h0Var;
    }

    public void subscribeToContentCardsUpdates(IEventSubscriber<ContentCardsUpdatedEvent> subscriber) {
        Intrinsics.checkNotNullParameter(subscriber, "subscriber");
        try {
            ((com.braze.events.d) this.externalIEventMessenger).d(ContentCardsUpdatedEvent.class, subscriber);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new A(0), 4, (Object) null);
            publishError(e);
        }
    }

    public void subscribeToFeedUpdates(IEventSubscriber<FeedUpdatedEvent> subscriber) {
        Intrinsics.checkNotNullParameter(subscriber, "subscriber");
        try {
            ((com.braze.events.d) this.externalIEventMessenger).d(FeedUpdatedEvent.class, subscriber);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new A(5), 4, (Object) null);
            publishError(e);
        }
    }

    public void subscribeToNewInAppMessages(IEventSubscriber<InAppMessageEvent> subscriber) {
        Intrinsics.checkNotNullParameter(subscriber, "subscriber");
        try {
            ((com.braze.events.d) this.externalIEventMessenger).d(InAppMessageEvent.class, subscriber);
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new C(3), 4, (Object) null);
            publishError(e);
        }
    }

    public final /* synthetic */ boolean validateAndStorePushId$android_sdk_base_release(String pushId) {
        Intrinsics.checkNotNullParameter(pushId, "pushId");
        return ((Boolean) runForResult$android_sdk_base_release$default(this, Boolean.TRUE, new C(11), false, false, new C1532y(this, pushId, null), 12, null)).booleanValue();
    }

    public void changeUser(String str, String str2) {
        run$android_sdk_base_release$default(this, new androidx.navigation.internal.l(str, 12), false, false, new C1482h(str, this, str2, 1), 6, null);
    }

    public void requestContentCardsRefresh() {
        run$android_sdk_base_release$default(this, new androidx.lifecycle.compose.f(27), false, false, new C1509o(this, 2), 6, null);
    }
}
