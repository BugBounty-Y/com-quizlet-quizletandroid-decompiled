package com.google.firebase.messaging;

import android.annotation.SuppressLint;
import android.app.Application;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.T;
import com.braze.L;
import com.google.android.gms.cloudmessaging.CloudMessage;
import com.google.android.gms.internal.ads.RunnableC1782Ud;
import com.google.android.gms.internal.mlkit_vision_common.A4;
import com.google.android.gms.internal.mlkit_vision_common.B4;
import com.google.android.gms.internal.mlkit_vision_common.C4;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.measurement.internal.C0;
import com.google.android.gms.tasks.Task;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class FirebaseMessaging {
    private static final String EXTRA_DUMMY_P_INTENT = "app";
    static final String GMS_PACKAGE = "com.google.android.gms";

    @Deprecated
    public static final String INSTANCE_ID_SCOPE = "FCM";
    private static final long MIN_DELAY_SEC = 30;
    private static final String SEND_INTENT_ACTION = "com.google.android.gcm.intent.SEND";
    private static final String SUBTYPE_DEFAULT = "";
    static final String TAG = "FirebaseMessaging";
    private static w store;
    static ScheduledExecutorService syncExecutor;
    private final l autoInit;
    private final Context context;
    private final Executor fileExecutor;
    private final com.google.firebase.h firebaseApp;
    private final m gmsRpc;
    private final com.google.firebase.iid.internal.a iid;
    private final Executor initExecutor;
    private final Application.ActivityLifecycleCallbacks lifecycleCallbacks;
    private final o metadata;
    private final t requestDeduplicator;
    private boolean syncScheduledOrRunning;
    private final Task<A> topicsSubscriberTask;
    private static final long MAX_DELAY_SEC = TimeUnit.HOURS.toSeconds(8);
    static com.google.firebase.inject.b transportFactory = new com.google.firebase.components.f(7);

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public FirebaseMessaging(com.google.firebase.h hVar, com.google.firebase.iid.internal.a aVar, com.google.firebase.inject.b bVar, com.google.firebase.inject.b bVar2, com.google.firebase.installations.d dVar, com.google.firebase.inject.b bVar3, com.google.firebase.events.c cVar) {
        this(hVar, aVar, bVar, bVar2, dVar, bVar3, cVar, new o(hVar.a));
        hVar.a();
    }

    public static synchronized void clearStoreForTest() {
        store = null;
    }

    public static void clearTransportFactoryForTest() {
        transportFactory = new com.google.firebase.components.f(6);
    }

    @NonNull
    public static synchronized FirebaseMessaging getInstance() {
        return getInstance(com.google.firebase.h.c());
    }

    @NonNull
    private static synchronized w getStore(Context context) {
        try {
            if (store == null) {
                store = new w(context);
            }
        } catch (Throwable th) {
            throw th;
        }
        return store;
    }

    private String getSubtype() {
        com.google.firebase.h hVar = this.firebaseApp;
        hVar.a();
        return "[DEFAULT]".equals(hVar.b) ? "" : this.firebaseApp.d();
    }

    public static com.google.android.datatransport.f getTransportFactory() {
        return (com.google.android.datatransport.f) transportFactory.get();
    }

    private void handleProxiedNotificationData() {
        Task taskH;
        int i;
        com.google.android.gms.cloudmessaging.a aVar = this.gmsRpc.c;
        if (aVar.c.a() >= 241100000) {
            com.google.android.gms.cloudmessaging.k kVarP = com.google.android.gms.cloudmessaging.k.p(aVar.b);
            Bundle bundle = Bundle.EMPTY;
            synchronized (kVarP) {
                i = kVarP.b;
                kVarP.b = i + 1;
            }
            taskH = kVarP.q(new com.google.android.gms.cloudmessaging.j(i, 5, bundle, 1)).e(com.google.android.gms.cloudmessaging.f.c, com.google.android.gms.cloudmessaging.c.c);
        } else {
            taskH = S3.h(new IOException("SERVICE_NOT_AVAILABLE"));
        }
        taskH.d(this.initExecutor, new i(this, 2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initializeProxyNotifications, reason: merged with bridge method [inline-methods] */
    public void lambda$new$4() {
        B4.c(this.context);
        C4.f(this.context, this.gmsRpc, shouldRetainProxyNotifications());
        if (shouldRetainProxyNotifications()) {
            handleProxiedNotificationData();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invokeOnTokenRefresh, reason: merged with bridge method [inline-methods] */
    public void lambda$new$1(String str) {
        com.google.firebase.h hVar = this.firebaseApp;
        hVar.a();
        if ("[DEFAULT]".equals(hVar.b)) {
            if (Log.isLoggable(TAG, 3)) {
                this.firebaseApp.a();
            }
            Intent intent = new Intent("com.google.firebase.messaging.NEW_TOKEN");
            intent.putExtra("token", str);
            new h(this.context).b(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public Task lambda$blockingGetToken$13(String str, v vVar, String str2) throws Exception {
        w store2 = getStore(this.context);
        String subtype = getSubtype();
        String strA = this.metadata.a();
        synchronized (store2) {
            String strA2 = v.a(System.currentTimeMillis(), str2, strA);
            if (strA2 != null) {
                SharedPreferences.Editor editorEdit = store2.a.edit();
                editorEdit.putString(w.a(subtype, str), strA2);
                editorEdit.commit();
            }
        }
        if (vVar == null || !str2.equals(vVar.a)) {
            lambda$new$1(str2);
        }
        return S3.i(str2);
    }

    private Task lambda$blockingGetToken$14(String str, v vVar) {
        m mVar = this.gmsRpc;
        return mVar.a(mVar.c(o.b(mVar.a), "*", new Bundle())).n(this.fileExecutor, new T(this, str, vVar, 13));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ com.google.android.datatransport.f lambda$clearTransportFactoryForTest$12() {
        return null;
    }

    private /* synthetic */ void lambda$deleteToken$8(com.google.android.gms.tasks.f fVar) {
        try {
            o.b(this.firebaseApp);
            throw null;
        } catch (Exception e) {
            fVar.a(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$deleteToken$9(com.google.android.gms.tasks.f fVar) {
        try {
            m mVar = this.gmsRpc;
            mVar.getClass();
            Bundle bundle = new Bundle();
            bundle.putString("delete", "1");
            S3.e(mVar.a(mVar.c(o.b(mVar.a), "*", bundle)));
            w store2 = getStore(this.context);
            String subtype = getSubtype();
            String strB = o.b(this.firebaseApp);
            synchronized (store2) {
                String strA = w.a(subtype, strB);
                SharedPreferences.Editor editorEdit = store2.a.edit();
                editorEdit.remove(strA);
                editorEdit.commit();
            }
            fVar.b(null);
        } catch (Exception e) {
            fVar.a(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$getToken$7(com.google.android.gms.tasks.f fVar) {
        try {
            fVar.b(blockingGetToken());
        } catch (Exception e) {
            fVar.a(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void lambda$handleProxiedNotificationData$5(CloudMessage cloudMessage) {
        if (cloudMessage != null) {
            A4.c(cloudMessage.a);
            handleProxiedNotificationData();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$new$2() {
        if (isAutoInitEnabled()) {
            startSyncIfNecessary();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$new$3(A a) {
        if (isAutoInitEnabled()) {
            a.f();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public /* synthetic */ void lambda$setNotificationDelegationEnabled$6(Void r3) {
        C4.f(this.context, this.gmsRpc, shouldRetainProxyNotifications());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ com.google.android.datatransport.f lambda$static$0() {
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Task lambda$subscribeToTopic$10(String str, A a) throws Exception {
        a.getClass();
        com.google.android.gms.tasks.m mVarD = a.d(new x("S", str));
        a.f();
        return mVarD;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Task lambda$unsubscribeFromTopic$11(String str, A a) throws Exception {
        a.getClass();
        com.google.android.gms.tasks.m mVarD = a.d(new x("U", str));
        a.f();
        return mVarD;
    }

    private boolean shouldRetainProxyNotifications() {
        B4.c(this.context);
        if (!B4.d(this.context)) {
            return false;
        }
        if (this.firebaseApp.b(com.google.firebase.analytics.connector.b.class) != null) {
            return true;
        }
        return A4.b() && transportFactory != null;
    }

    private synchronized void startSync() {
        if (!this.syncScheduledOrRunning) {
            syncWithDelaySecondsInternal(0L);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startSyncIfNecessary() {
        if (tokenNeedsRefresh(getTokenWithoutTriggeringSync())) {
            startSync();
        }
    }

    public String blockingGetToken() throws IOException {
        Task taskF;
        v tokenWithoutTriggeringSync = getTokenWithoutTriggeringSync();
        if (!tokenNeedsRefresh(tokenWithoutTriggeringSync)) {
            return tokenWithoutTriggeringSync.a;
        }
        String strB = o.b(this.firebaseApp);
        t tVar = this.requestDeduplicator;
        synchronized (tVar) {
            taskF = (Task) tVar.b.get(strB);
            if (taskF != null) {
                Log.isLoggable(TAG, 3);
            } else {
                Log.isLoggable(TAG, 3);
                taskF = lambda$blockingGetToken$14(strB, tokenWithoutTriggeringSync).f(tVar.a, new C0143u(24, tVar, strB));
                tVar.b.put(strB, taskF);
            }
        }
        try {
            return (String) S3.e(taskF);
        } catch (InterruptedException | ExecutionException e) {
            throw new IOException(e);
        }
    }

    @NonNull
    public Task<Void> deleteToken() {
        if (getTokenWithoutTriggeringSync() == null) {
            return S3.i(null);
        }
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        Executors.newSingleThreadExecutor(new com.android.billingclient.api.p("Firebase-Messaging-Network-Io", 2)).execute(new k(this, fVar, 1));
        return fVar.a;
    }

    @NonNull
    public boolean deliveryMetricsExportToBigQueryEnabled() {
        return A4.b();
    }

    @SuppressLint({"ThreadPoolCreation"})
    public void enqueueTaskWithDelaySeconds(Runnable runnable, long j) {
        synchronized (FirebaseMessaging.class) {
            try {
                if (syncExecutor == null) {
                    syncExecutor = new ScheduledThreadPoolExecutor(1, new com.android.billingclient.api.p("TAG", 2));
                }
                syncExecutor.schedule(runnable, j, TimeUnit.SECONDS);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public Context getApplicationContext() {
        return this.context;
    }

    @NonNull
    public Task<String> getToken() {
        com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
        this.initExecutor.execute(new k(this, fVar, 0));
        return fVar.a;
    }

    public v getTokenWithoutTriggeringSync() {
        v vVarB;
        w store2 = getStore(this.context);
        String subtype = getSubtype();
        String strB = o.b(this.firebaseApp);
        synchronized (store2) {
            vVarB = v.b(store2.a.getString(w.a(subtype, strB), null));
        }
        return vVarB;
    }

    public Task<A> getTopicsSubscriberTask() {
        return this.topicsSubscriberTask;
    }

    public boolean isAutoInitEnabled() {
        boolean zBooleanValue;
        l lVar = this.autoInit;
        synchronized (lVar) {
            try {
                lVar.a();
                Boolean bool = lVar.d;
                zBooleanValue = bool != null ? bool.booleanValue() : lVar.e.firebaseApp.h();
            } catch (Throwable th) {
                throw th;
            }
        }
        return zBooleanValue;
    }

    public boolean isGmsCorePresent() {
        return this.metadata.d();
    }

    public boolean isNotificationDelegationEnabled() {
        return B4.d(this.context);
    }

    @Deprecated
    public void send(@NonNull RemoteMessage remoteMessage) {
        if (TextUtils.isEmpty(remoteMessage.a.getString("google.to"))) {
            throw new IllegalArgumentException("Missing 'to'");
        }
        Intent intent = new Intent(SEND_INTENT_ACTION);
        Intent intent2 = new Intent();
        intent2.setPackage("com.google.example.invalidpackage");
        intent.putExtra(EXTRA_DUMMY_P_INTENT, PendingIntent.getBroadcast(this.context, 0, intent2, 67108864));
        intent.setPackage(GMS_PACKAGE);
        intent.putExtras(remoteMessage.a);
        this.context.sendOrderedBroadcast(intent, "com.google.android.gtalkservice.permission.GTALK_SERVICE");
    }

    public void setAutoInitEnabled(boolean z) {
        l lVar = this.autoInit;
        synchronized (lVar) {
            try {
                lVar.a();
                com.google.firebase.components.n nVar = lVar.c;
                if (nVar != null) {
                    ((com.google.firebase.components.k) lVar.a).b(nVar);
                    lVar.c = null;
                }
                com.google.firebase.h hVar = lVar.e.firebaseApp;
                hVar.a();
                SharedPreferences.Editor editorEdit = hVar.a.getSharedPreferences("com.google.firebase.messaging", 0).edit();
                editorEdit.putBoolean("auto_init", z);
                editorEdit.apply();
                if (z) {
                    lVar.e.startSyncIfNecessary();
                }
                lVar.d = Boolean.valueOf(z);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void setDeliveryMetricsExportToBigQuery(boolean z) {
        com.google.firebase.h hVarC = com.google.firebase.h.c();
        hVarC.a();
        hVarC.a.getSharedPreferences("com.google.firebase.messaging", 0).edit().putBoolean("export_to_big_query", z).apply();
        C4.f(this.context, this.gmsRpc, shouldRetainProxyNotifications());
    }

    @NonNull
    public Task<Void> setNotificationDelegationEnabled(boolean z) {
        com.google.android.gms.tasks.m mVarI;
        Executor executor = this.initExecutor;
        Context context = this.context;
        if (Build.VERSION.SDK_INT >= 29) {
            com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
            executor.execute(new r(context, z, fVar));
            mVarI = fVar.a;
        } else {
            mVarI = S3.i(null);
        }
        mVarI.d(new androidx.arch.core.executor.a(1), new i(this, 1));
        return mVarI;
    }

    public synchronized void setSyncScheduledOrRunning(boolean z) {
        this.syncScheduledOrRunning = z;
    }

    @NonNull
    @SuppressLint({"TaskMainThread"})
    public Task<Void> subscribeToTopic(@NonNull String str) {
        return this.topicsSubscriberTask.m(new L(str, 2));
    }

    public synchronized void syncWithDelaySecondsInternal(long j) {
        enqueueTaskWithDelaySeconds(new RunnableC1782Ud(this, Math.min(Math.max(MIN_DELAY_SEC, 2 * j), MAX_DELAY_SEC)), j);
        this.syncScheduledOrRunning = true;
    }

    public boolean tokenNeedsRefresh(v vVar) {
        if (vVar != null) {
            return System.currentTimeMillis() > vVar.c + v.d || !this.metadata.a().equals(vVar.b);
        }
        return true;
    }

    @NonNull
    @SuppressLint({"TaskMainThread"})
    public Task<Void> unsubscribeFromTopic(@NonNull String str) {
        return this.topicsSubscriberTask.m(new L(str, 3));
    }

    @NonNull
    @Keep
    public static synchronized FirebaseMessaging getInstance(@NonNull com.google.firebase.h hVar) {
        FirebaseMessaging firebaseMessaging;
        firebaseMessaging = (FirebaseMessaging) hVar.b(FirebaseMessaging.class);
        com.google.android.gms.common.internal.u.i(firebaseMessaging, "Firebase Messaging component is not present");
        return firebaseMessaging;
    }

    public FirebaseMessaging(com.google.firebase.h hVar, com.google.firebase.iid.internal.a aVar, com.google.firebase.inject.b bVar, com.google.firebase.inject.b bVar2, com.google.firebase.installations.d dVar, com.google.firebase.inject.b bVar3, com.google.firebase.events.c cVar, o oVar) {
        this(hVar, aVar, bVar3, cVar, oVar, new m(hVar, oVar, bVar, bVar2, dVar), Executors.newSingleThreadExecutor(new com.android.billingclient.api.p("Firebase-Messaging-Task", 2)), new ScheduledThreadPoolExecutor(1, new com.android.billingclient.api.p("Firebase-Messaging-Init", 2)), new ThreadPoolExecutor(0, 1, MIN_DELAY_SEC, TimeUnit.SECONDS, new LinkedBlockingQueue(), new com.android.billingclient.api.p("Firebase-Messaging-File-Io", 2)));
    }

    public FirebaseMessaging(com.google.firebase.h hVar, com.google.firebase.iid.internal.a aVar, com.google.firebase.inject.b bVar, com.google.firebase.events.c cVar, final o oVar, final m mVar, Executor executor, Executor executor2, Executor executor3) {
        final int i = 1;
        final int i2 = 0;
        this.syncScheduledOrRunning = false;
        transportFactory = bVar;
        this.firebaseApp = hVar;
        this.autoInit = new l(this, cVar);
        hVar.a();
        final Context context = hVar.a;
        this.context = context;
        C0 c0 = new C0();
        this.lifecycleCallbacks = c0;
        this.metadata = oVar;
        this.gmsRpc = mVar;
        this.requestDeduplicator = new t(executor);
        this.initExecutor = executor2;
        this.fileExecutor = executor3;
        hVar.a();
        Context context2 = hVar.a;
        if (context2 instanceof Application) {
            ((Application) context2).registerActivityLifecycleCallbacks(c0);
        } else {
            Log.w(TAG, "Context " + context2 + " was not an application, can't register for lifecycle callbacks. Some notification events may be dropped as a result.");
        }
        if (aVar != null) {
            aVar.a();
        }
        executor2.execute(new Runnable(this) { // from class: com.google.firebase.messaging.j
            public final /* synthetic */ FirebaseMessaging b;

            {
                this.b = this;
            }

            @Override // java.lang.Runnable
            public final void run() {
                switch (i) {
                    case 0:
                        this.b.lambda$new$4();
                        break;
                    default:
                        this.b.lambda$new$2();
                        break;
                }
            }
        });
        final ScheduledThreadPoolExecutor scheduledThreadPoolExecutor = new ScheduledThreadPoolExecutor(1, new com.android.billingclient.api.p("Firebase-Messaging-Topics-Io", 2));
        int i3 = A.j;
        com.google.android.gms.tasks.m mVarG = S3.g(scheduledThreadPoolExecutor, new Callable() { // from class: com.google.firebase.messaging.z
            @Override // java.util.concurrent.Callable
            public final Object call() {
                y yVar;
                Context context3 = context;
                ScheduledThreadPoolExecutor scheduledThreadPoolExecutor2 = scheduledThreadPoolExecutor;
                FirebaseMessaging firebaseMessaging = this;
                o oVar2 = oVar;
                m mVar2 = mVar;
                synchronized (y.class) {
                    try {
                        WeakReference weakReference = y.c;
                        yVar = weakReference != null ? (y) weakReference.get() : null;
                        if (yVar == null) {
                            SharedPreferences sharedPreferences = context3.getSharedPreferences("com.google.android.gms.appid", 0);
                            y yVar2 = new y(sharedPreferences, scheduledThreadPoolExecutor2);
                            synchronized (yVar2) {
                                yVar2.a = com.quizlet.remote.model.notes.e.j(sharedPreferences, scheduledThreadPoolExecutor2);
                            }
                            y.c = new WeakReference(yVar2);
                            yVar = yVar2;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return new A(firebaseMessaging, oVar2, yVar, mVar2, context3, scheduledThreadPoolExecutor2);
            }
        });
        this.topicsSubscriberTask = mVarG;
        mVarG.d(executor2, new i(this, i2));
        executor2.execute(new Runnable(this) { // from class: com.google.firebase.messaging.j
            public final /* synthetic */ FirebaseMessaging b;

            {
                this.b = this;
            }

            @Override // java.lang.Runnable
            public final void run() {
                switch (i2) {
                    case 0:
                        this.b.lambda$new$4();
                        break;
                    default:
                        this.b.lambda$new$2();
                        break;
                }
            }
        });
    }
}
