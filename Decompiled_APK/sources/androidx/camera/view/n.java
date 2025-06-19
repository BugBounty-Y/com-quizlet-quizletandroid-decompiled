package androidx.camera.view;

import android.content.Context;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import androidx.annotation.NonNull;
import androidx.camera.core.J;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class n extends View {
    public Window a;
    public m b;

    public n(@NonNull Context context) {
        super(context, null, 0, 0);
        setBackgroundColor(-1);
        setAlpha(DefinitionKt.NO_Float_VALUE);
        setElevation(Float.MAX_VALUE);
    }

    private float getBrightness() {
        Window window = this.a;
        if (window != null) {
            return window.getAttributes().screenBrightness;
        }
        AbstractC3053s1.c("ScreenFlashView", "setBrightness: mScreenFlashWindow is null!");
        return Float.NaN;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setBrightness(float f) {
        if (this.a == null) {
            AbstractC3053s1.c("ScreenFlashView", "setBrightness: mScreenFlashWindow is null!");
            return;
        }
        if (Float.isNaN(f)) {
            AbstractC3053s1.c("ScreenFlashView", "setBrightness: value is NaN!");
            return;
        }
        WindowManager.LayoutParams attributes = this.a.getAttributes();
        attributes.screenBrightness = f;
        this.a.setAttributes(attributes);
        AbstractC3053s1.f(3, "ScreenFlashView");
    }

    private void setScreenFlashUiInfo(J j) {
        AbstractC3053s1.f(3, "ScreenFlashView");
    }

    public J getScreenFlash() {
        return this.b;
    }

    public long getVisibilityRampUpAnimationDurationMillis() {
        return 1000L;
    }

    public void setController(a aVar) {
        S.d();
    }

    public void setScreenFlashWindow(Window window) {
        S.d();
        if (this.a != window) {
            this.b = window == null ? null : new m(this);
        }
        this.a = window;
        setScreenFlashUiInfo(getScreenFlash());
    }
}
