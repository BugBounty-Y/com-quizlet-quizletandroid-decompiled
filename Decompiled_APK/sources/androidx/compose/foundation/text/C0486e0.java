package androidx.compose.foundation.text;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.e0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0486e0 {
    public final androidx.compose.ui.platform.Q0 a;
    public C0488f0 b;
    public androidx.compose.ui.focus.h c;

    public C0486e0(androidx.compose.ui.platform.Q0 q0) {
        this.a = q0;
    }

    public final C0488f0 a() {
        C0488f0 c0488f0 = this.b;
        if (c0488f0 != null) {
            return c0488f0;
        }
        Intrinsics.m("keyboardActions");
        throw null;
    }
}
