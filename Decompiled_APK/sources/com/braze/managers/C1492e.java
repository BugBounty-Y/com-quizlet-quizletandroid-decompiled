package com.braze.managers;

import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.managers.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1492e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeGeofenceManager b;

    public /* synthetic */ C1492e(BrazeGeofenceManager brazeGeofenceManager, int i) {
        this.a = i;
        this.b = brazeGeofenceManager;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeGeofenceManager.configureFromServerConfig$lambda$28(this.b);
            case 1:
                return BrazeGeofenceManager.configureFromServerConfig$lambda$30(this.b);
            case 2:
                return BrazeGeofenceManager.registerGeofences$lambda$37$lambda$34(this.b);
            default:
                return BrazeGeofenceManager.registerGeofences$lambda$37$lambda$36(this.b);
        }
    }
}
