package androidx.glance.session;

import android.os.PowerManager;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.glance.session.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1224b {
    public static final C1224b a = new C1224b();

    public final boolean a(@NotNull PowerManager powerManager) {
        return powerManager.isLowPowerStandbyEnabled() || powerManager.isDeviceLightIdleMode();
    }
}
