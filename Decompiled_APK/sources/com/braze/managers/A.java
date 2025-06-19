package com.braze.managers;

import com.braze.managers.BrazeGeofenceManager;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class A implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ A(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeGeofenceManager.configureFromServerConfig$lambda$29(false);
            case 1:
                return BrazeGeofenceManager.registerGeofences$lambda$31();
            case 2:
                return BrazeGeofenceManager._init_$lambda$1();
            case 3:
                return BrazeGeofenceManager.requestGeofenceRefresh$lambda$26();
            case 4:
                return BrazeGeofenceManager.onLocationRequestComplete$lambda$40(null);
            case 5:
                return BrazeGeofenceManager.onLocationRequestComplete$lambda$41();
            case 6:
                return BrazeGeofenceManager.requestGeofenceRefresh$lambda$24();
            case 7:
                return BrazeGeofenceManager.isGeofencesEnabledFromEnvironment$lambda$4();
            case 8:
                return BrazeGeofenceManager.isGeofencesEnabledFromEnvironment$lambda$5();
            case 9:
                return BrazeGeofenceManager.isGeofencesEnabledFromEnvironment$lambda$6();
            case 10:
                return BrazeGeofenceManager.isGeofencesEnabledFromEnvironment$lambda$7();
            case 11:
                return BrazeGeofenceManager.isGeofencesEnabledFromEnvironment$lambda$8();
            case 12:
                return BrazeGeofenceManager.unregisterGeofences$lambda$38();
            case 13:
                return BrazeGeofenceManager.unregisterGeofences$lambda$39();
            case 14:
                return BrazeGeofenceManager.setUpGeofences$lambda$11();
            case 15:
                return BrazeGeofenceManager.Companion.retrieveBrazeGeofencesFromLocalStorage$lambda$4();
            case 16:
                return BrazeGeofenceManager.Companion.retrieveBrazeGeofencesFromLocalStorage$lambda$3();
            case 17:
                return BrazeGeofenceManager.Companion.getGeofencesEnabledFromServerConfig$lambda$0();
            case 18:
                return BrazeGeofenceManager.Companion.getGeofencesEnabledFromServerConfig$lambda$1();
            case 19:
                return BrazeGeofenceManager.Companion.getGeofencesEnabledFromServerConfig$lambda$2();
            case 20:
                return C1488a.b();
            case 21:
                return a0.b();
            case EventType.WINDOW_STATE /* 22 */:
                return a0.i();
            case EventType.AUDIO /* 23 */:
                return a0.j();
            case EventType.VIDEO /* 24 */:
                return a0.e();
            case EventType.SUBS /* 25 */:
                return a0.d();
            case EventType.CDN /* 26 */:
                return C1489b.b();
            case 27:
                return Boolean.valueOf(b0.c());
            case 28:
                return b0.f();
            default:
                return b0.g();
        }
    }
}
