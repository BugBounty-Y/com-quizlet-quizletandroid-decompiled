package androidx.glance.session;

import android.os.PowerManager;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.glance.session.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1223a {
    public static final C1223a a = new C1223a();

    public final boolean a(@NotNull PowerManager powerManager) {
        return powerManager.isDeviceIdleMode();
    }
}
