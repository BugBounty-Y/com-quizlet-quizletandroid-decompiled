package com.google.firebase.components;

import android.os.StrictMode;
import com.google.firebase.concurrent.ExecutorsRegistrar;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.perf.session.gauges.GaugeManager;
import java.util.Collections;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements com.google.firebase.inject.b {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.inject.b
    public final Object get() {
        switch (this.a) {
            case 0:
                return Collections.EMPTY_SET;
            case 1:
                return null;
            case 2:
                l lVar = ExecutorsRegistrar.a;
                StrictMode.ThreadPolicy.Builder builderDetectNetwork = new StrictMode.ThreadPolicy.Builder().detectNetwork();
                builderDetectNetwork.detectResourceMismatches();
                builderDetectNetwork.detectUnbufferedIo();
                return new com.google.firebase.concurrent.e(Executors.newFixedThreadPool(4, new com.google.firebase.concurrent.a("Firebase Background", 10, builderDetectNetwork.penaltyLog().build())), (ScheduledExecutorService) ExecutorsRegistrar.d.get());
            case 3:
                l lVar2 = ExecutorsRegistrar.a;
                return new com.google.firebase.concurrent.e(Executors.newFixedThreadPool(Math.max(2, Runtime.getRuntime().availableProcessors()), new com.google.firebase.concurrent.a("Firebase Lite", 0, new StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build())), (ScheduledExecutorService) ExecutorsRegistrar.d.get());
            case 4:
                l lVar3 = ExecutorsRegistrar.a;
                return new com.google.firebase.concurrent.e(Executors.newCachedThreadPool(new com.google.firebase.concurrent.a("Firebase Blocking", 11, null)), (ScheduledExecutorService) ExecutorsRegistrar.d.get());
            case 5:
                l lVar4 = ExecutorsRegistrar.a;
                return Executors.newSingleThreadScheduledExecutor(new com.google.firebase.concurrent.a("Firebase Scheduler", 0, null));
            case 6:
                return FirebaseMessaging.lambda$clearTransportFactoryForTest$12();
            case 7:
                return FirebaseMessaging.lambda$static$0();
            case 8:
                return Executors.newSingleThreadScheduledExecutor();
            case 9:
                return GaugeManager.lambda$new$0();
            case 10:
                return GaugeManager.lambda$new$1();
            default:
                Random random = com.google.firebase.remoteconfig.f.j;
                return null;
        }
    }
}
