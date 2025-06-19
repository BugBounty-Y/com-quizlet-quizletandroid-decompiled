package androidx.compose.ui.platform;

import android.content.Context;
import android.view.accessibility.AccessibilityManager;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0940f implements InterfaceC0938e {
    public final AccessibilityManager a;

    public C0940f(@NotNull Context context) {
        Object systemService = context.getSystemService("accessibility");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.accessibility.AccessibilityManager");
        this.a = (AccessibilityManager) systemService;
    }
}
