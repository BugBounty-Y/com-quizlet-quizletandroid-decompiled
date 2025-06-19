package com.braze;

import androidx.compose.runtime.C0776c;
import com.braze.Braze;
import com.braze.images.DefaultBrazeImageLoader;
import com.braze.managers.BrazeGeofenceManager;
import com.braze.storage.a0;
import com.braze.ui.inappmessage.InAppMessageManagerBase;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1483i implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;

    public /* synthetic */ C1483i(boolean z, int i) {
        this.a = i;
        this.b = z;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.requestGeofenceRefresh$lambda$176(this.b);
            case 1:
                return Braze.setSyncPolicyOfflineStatus$lambda$209(this.b);
            case 2:
                return Braze.setSyncPolicyOfflineStatus$lambda$211$lambda$210(this.b);
            case 3:
                return Braze.Companion._set_outboundNetworkRequestsOffline_$lambda$0(this.b);
            case 4:
                return DefaultBrazeImageLoader.setOffline$lambda$0(this.b);
            case 5:
                return BrazeGeofenceManager.setUpGeofences$lambda$12(this.b);
            case 6:
                return BrazeGeofenceManager.configureFromServerConfig$lambda$27(this.b);
            case 7:
                return a0.a(this.b);
            case 8:
                return InAppMessageManagerBase._set_shouldNextUnregisterBeSkipped_$lambda$0(this.b);
            case 9:
                return C0776c.z(Boolean.valueOf(this.b));
            case 10:
                return C0776c.z(Boolean.valueOf(this.b));
            case 11:
                return C0776c.z(Boolean.valueOf(this.b));
            case 12:
                return C0776c.z(Boolean.valueOf(this.b));
            case 13:
                return C0776c.z(Boolean.valueOf(this.b));
            case 14:
                return C0776c.z(Boolean.valueOf(this.b));
            case 15:
                return C0776c.z(Boolean.valueOf(this.b));
            case 16:
                return C0776c.z(Boolean.valueOf(this.b));
            case 17:
                return Boolean.valueOf(this.b);
            case 18:
                return C0776c.z(Boolean.valueOf(this.b));
            default:
                return Boolean.valueOf(this.b);
        }
    }
}
