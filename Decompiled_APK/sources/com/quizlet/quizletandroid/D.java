package com.quizlet.quizletandroid;

import android.app.Application;
import android.app.NotificationManager;
import android.content.Context;
import android.os.Environment;
import android.os.StatFs;
import android.view.accessibility.AccessibilityManager;
import androidx.lifecycle.L;
import androidx.lifecycle.d0;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.messaging.FirebaseMessaging;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.KmpEventLogger;
import com.quizlet.eventlogger.NotificationDeviceStatus;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public abstract class D extends Application implements dagger.hilt.internal.b {
    public boolean a = false;
    public final dagger.hilt.android.internal.managers.f b = new dagger.hilt.android.internal.managers.f(new com.lyft.android.scissors.b(this, 28));

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return this.b.d();
    }

    @Override // android.app.Application
    public void onCreate() {
        if (!this.a) {
            this.a = true;
            QuizletApplication quizletApplication = (QuizletApplication) this;
            u uVar = (u) ((F) this.b.d());
            quizletApplication.c = (com.squareup.otto.c) uVar.x.get();
            FirebaseMessaging firebaseMessaging = (FirebaseMessaging) uVar.V.get();
            io.reactivex.rxjava3.core.o scheduler = io.reactivex.rxjava3.schedulers.e.c;
            Intrinsics.checkNotNullExpressionValue(scheduler, "io(...)");
            S6.c(scheduler);
            Intrinsics.checkNotNullParameter(firebaseMessaging, "firebaseMessaging");
            Intrinsics.checkNotNullParameter(scheduler, "scheduler");
            quizletApplication.d = new com.quizlet.data.repository.widget.b(firebaseMessaging, scheduler);
            quizletApplication.e = uVar.w();
            quizletApplication.f = uVar.H0;
            quizletApplication.g = new androidx.hilt.work.a(com.google.common.collect.m.b("com.quizlet.background.eventlogging.EventLogSyncingWorker", uVar.J0, "com.quizlet.background.metering.MeteringSyncWorker", uVar.L0, "com.quizlet.background.progress.ProgressResetSyncWorker", uVar.M0, "com.quizlet.background.widget.WidgetUpdateWorker", uVar.O0));
            com.quizlet.quizletandroid.logging.initializer.a aVar = new com.quizlet.quizletandroid.logging.initializer.a(0);
            com.google.firebase.crashlytics.b firebaseCrashlytics = (com.google.firebase.crashlytics.b) uVar.t.get();
            Intrinsics.checkNotNullParameter(firebaseCrashlytics, "firebaseCrashlytics");
            com.onetrust.otpublishers.headless.UI.fragment.q crashlyticsLogger = new com.onetrust.otpublishers.headless.UI.fragment.q();
            crashlyticsLogger.b = firebaseCrashlytics;
            com.quizlet.db.token.a accessTokenManager = (com.quizlet.db.token.a) uVar.u.get();
            Intrinsics.checkNotNullParameter(crashlyticsLogger, "crashlyticsLogger");
            Intrinsics.checkNotNullParameter(accessTokenManager, "accessTokenManager");
            com.quizlet.local.ormlite.models.term.b loggingInitializer = new com.quizlet.local.ormlite.models.term.b(aVar, new com.quizlet.android.logging.a(crashlyticsLogger, accessTokenManager));
            com.quizlet.infra.legacysyncengine.net.request.g globalRxErrorHandler = new com.quizlet.infra.legacysyncengine.net.request.g(1);
            com.google.firebase.perf.logging.b ormLiteInitializer = new com.google.firebase.perf.logging.b(28);
            Context contextQ = uVar.q();
            Context context = uVar.q();
            Intrinsics.checkNotNullParameter(context, "context");
            Object systemService = context.getSystemService("notification");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
            com.quizlet.data.repository.qclass.c notificationChannelsManager = new com.quizlet.data.repository.qclass.c((NotificationManager) systemService, contextQ);
            com.quizlet.billing.manager.f inAppBillingManager = (com.quizlet.billing.manager.f) uVar.s0.get();
            L applicationLifecycle = d0.i.f;
            S6.c(applicationLifecycle);
            com.quizlet.braze.c brazeSDKManager = (com.quizlet.braze.c) uVar.P0.get();
            androidx.webkit.internal.p analyticsInitializer = new androidx.webkit.internal.p((com.quizlet.usecase.a) uVar.o.get());
            com.quizlet.features.consent.onetrust.d consentManager = (com.quizlet.features.consent.onetrust.d) uVar.R0.get();
            Context context2 = uVar.q();
            com.quizlet.local.sqldelight.a kmpDatabaseDriverFactory = new com.quizlet.local.sqldelight.a(uVar.q());
            okhttp3.A okHttpClient = (okhttp3.A) uVar.N.get();
            KmpEventLogger kmpEventLogger = new KmpEventLogger((EventLogger) uVar.l0.get());
            com.quizlet.featuregate.experimentmanager.a aVar2 = com.quizlet.featuregate.experimentmanager.a.a;
            com.google.mlkit.common.sdkinternal.model.a apiUrlProvider = new com.google.mlkit.common.sdkinternal.model.a(29);
            Context context3 = uVar.a.a;
            S6.c(context3);
            androidx.work.impl.model.i cacheSizeCalculator = new androidx.work.impl.model.i(context3, new StatFs(Environment.getDataDirectory().getPath()));
            com.quizlet.featuregate.experimentmanager.a androidRawExperimentManager = com.quizlet.featuregate.experimentmanager.a.a;
            Intrinsics.checkNotNullParameter(context2, "context");
            Intrinsics.checkNotNullParameter(kmpDatabaseDriverFactory, "kmpDatabaseDriverFactory");
            Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
            Intrinsics.checkNotNullParameter(kmpEventLogger, "kmpEventLogger");
            Intrinsics.checkNotNullParameter(androidRawExperimentManager, "androidRawExperimentManager");
            Intrinsics.checkNotNullParameter(apiUrlProvider, "apiUrlProvider");
            Intrinsics.checkNotNullParameter(cacheSizeCalculator, "cacheSizeCalculator");
            C1608n kmpDependencyProvider = new C1608n();
            kmpDependencyProvider.a = context2;
            kmpDependencyProvider.b = kmpDatabaseDriverFactory;
            kmpDependencyProvider.c = okHttpClient;
            kmpDependencyProvider.d = kmpEventLogger;
            kmpDependencyProvider.e = cacheSizeCalculator;
            com.quizlet.data.repository.set.f nightThemeManager = uVar.D0();
            kotlinx.coroutines.internal.d defaultScope = uVar.Q();
            kotlinx.coroutines.scheduling.e eVar = O.a;
            kotlinx.coroutines.android.d mainDispatcher = kotlinx.coroutines.internal.m.a;
            S6.c(mainDispatcher);
            Intrinsics.checkNotNullParameter(loggingInitializer, "loggingInitializer");
            Intrinsics.checkNotNullParameter(globalRxErrorHandler, "globalRxErrorHandler");
            Intrinsics.checkNotNullParameter(ormLiteInitializer, "ormLiteInitializer");
            Intrinsics.checkNotNullParameter(notificationChannelsManager, "notificationChannelsManager");
            Intrinsics.checkNotNullParameter(inAppBillingManager, "inAppBillingManager");
            Intrinsics.checkNotNullParameter(applicationLifecycle, "applicationLifecycle");
            Intrinsics.checkNotNullParameter(brazeSDKManager, "brazeSDKManager");
            Intrinsics.checkNotNullParameter(analyticsInitializer, "analyticsInitializer");
            Intrinsics.checkNotNullParameter(consentManager, "consentManager");
            Intrinsics.checkNotNullParameter(kmpDependencyProvider, "kmpDependencyProvider");
            Intrinsics.checkNotNullParameter(nightThemeManager, "nightThemeManager");
            Intrinsics.checkNotNullParameter(defaultScope, "defaultScope");
            Intrinsics.checkNotNullParameter(mainDispatcher, "mainDispatcher");
            androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j();
            jVar.a = loggingInitializer;
            jVar.b = globalRxErrorHandler;
            jVar.c = notificationChannelsManager;
            jVar.d = inAppBillingManager;
            jVar.e = brazeSDKManager;
            jVar.f = analyticsInitializer;
            jVar.g = consentManager;
            jVar.h = kmpDependencyProvider;
            jVar.i = nightThemeManager;
            jVar.j = defaultScope;
            quizletApplication.h = jVar;
            quizletApplication.i = uVar.Q();
            quizletApplication.j = dagger.internal.a.a(uVar.T0);
            kotlinx.coroutines.internal.d dVarQ = uVar.Q();
            S6.c(context3);
            EventLogger eventLogger = (EventLogger) uVar.l0.get();
            com.quizlet.data.repository.user.a aVarO = uVar.O();
            Context context4 = uVar.q();
            Intrinsics.checkNotNullParameter(context4, "context");
            Object systemService2 = context4.getSystemService("accessibility");
            Intrinsics.e(systemService2, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager");
            com.quizlet.data.interactor.school.b bVar = new com.quizlet.data.interactor.school.b((AccessibilityManager) systemService2, (EventLogger) uVar.l0.get());
            Context context5 = uVar.q();
            Intrinsics.checkNotNullParameter(context5, "context");
            NotificationDeviceStatus notificationDeviceStatus = new NotificationDeviceStatus(context5);
            Context contextQ2 = uVar.q();
            Context context6 = uVar.q();
            Intrinsics.checkNotNullParameter(context6, "context");
            Object systemService3 = context6.getSystemService("notification");
            Intrinsics.e(systemService3, "null cannot be cast to non-null type android.app.NotificationManager");
            quizletApplication.k = new com.quizlet.quizletandroid.logging.b(dVarQ, context3, eventLogger, aVarO, bVar, notificationDeviceStatus, new com.quizlet.data.repository.qclass.c((NotificationManager) systemService3, contextQ2), (ObjectMapper) uVar.E.get());
        }
        super.onCreate();
    }
}
