package androidx.compose.ui.platform;

import android.content.ClipboardManager;
import android.content.Context;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0942g implements InterfaceC0949j0 {
    public final ClipboardManager a;

    public C0942g(@NotNull Context context) {
        Object systemService = context.getSystemService("clipboard");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.content.ClipboardManager");
        this.a = (ClipboardManager) systemService;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00a6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.compose.ui.text.C0995g r17) {
        /*
            Method dump skipped, instructions count: 369
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0942g.a(androidx.compose.ui.text.g):void");
    }
}
