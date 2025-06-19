package androidx.compose.ui.platform;

import android.view.ViewConfiguration;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0939e0 {
    public static final C0939e0 a = new C0939e0();

    public final float a(@NotNull ViewConfiguration viewConfiguration) {
        return viewConfiguration.getScaledHandwritingGestureLineMargin();
    }

    public final float b(@NotNull ViewConfiguration viewConfiguration) {
        return viewConfiguration.getScaledHandwritingSlop();
    }
}
