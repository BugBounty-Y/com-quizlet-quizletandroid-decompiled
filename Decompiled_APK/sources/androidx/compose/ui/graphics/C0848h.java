package androidx.compose.ui.graphics;

import android.graphics.Bitmap;

/* renamed from: androidx.compose.ui.graphics.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0848h {
    public final Bitmap a;

    public C0848h(Bitmap bitmap) {
        this.a = bitmap;
    }

    public final int a() {
        Bitmap.Config config = this.a.getConfig();
        if (config == Bitmap.Config.ALPHA_8) {
            return 1;
        }
        if (config == Bitmap.Config.RGB_565) {
            return 2;
        }
        if (config == Bitmap.Config.ARGB_4444) {
            return 0;
        }
        if (config == Bitmap.Config.RGBA_F16) {
            return 3;
        }
        return config == Bitmap.Config.HARDWARE ? 4 : 0;
    }
}
