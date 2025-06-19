package androidx.compose.ui.platform;

import android.view.accessibility.AccessibilityManager;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0943g0 {
    public static final C0943g0 a = new C0943g0();

    public final int a(@NotNull AccessibilityManager accessibilityManager, int i, int i2) {
        return accessibilityManager.getRecommendedTimeoutMillis(i, i2);
    }
}
