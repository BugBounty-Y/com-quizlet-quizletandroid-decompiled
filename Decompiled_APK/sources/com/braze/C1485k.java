package com.braze;

import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1485k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Braze b;
    public final /* synthetic */ boolean c;

    public /* synthetic */ C1485k(Braze braze, boolean z, int i) {
        this.a = i;
        this.b = braze;
        this.c = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.requestGeofenceRefresh$lambda$177(this.b, this.c);
            default:
                return Braze.setSyncPolicyOfflineStatus$lambda$211(this.b, this.c);
        }
    }
}
