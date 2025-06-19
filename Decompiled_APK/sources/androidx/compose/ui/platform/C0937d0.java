package androidx.compose.ui.platform;

import android.os.Build;
import android.view.ViewConfiguration;

/* renamed from: androidx.compose.ui.platform.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0937d0 implements Y0 {
    public final ViewConfiguration a;

    public C0937d0(ViewConfiguration viewConfiguration) {
        this.a = viewConfiguration;
    }

    @Override // androidx.compose.ui.platform.Y0
    public final long a() {
        return ViewConfiguration.getDoubleTapTimeout();
    }

    @Override // androidx.compose.ui.platform.Y0
    public final long b() {
        return ViewConfiguration.getLongPressTimeout();
    }

    @Override // androidx.compose.ui.platform.Y0
    public final float c() {
        if (Build.VERSION.SDK_INT >= 34) {
            return C0939e0.a.b(this.a);
        }
        return 2.0f;
    }

    @Override // androidx.compose.ui.platform.Y0
    public final float e() {
        return this.a.getScaledMaximumFlingVelocity();
    }

    @Override // androidx.compose.ui.platform.Y0
    public final float f() {
        return this.a.getScaledTouchSlop();
    }

    @Override // androidx.compose.ui.platform.Y0
    public final float g() {
        if (Build.VERSION.SDK_INT >= 34) {
            return C0939e0.a.a(this.a);
        }
        return 16.0f;
    }
}
