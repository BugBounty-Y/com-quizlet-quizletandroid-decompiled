package androidx.compose.ui.platform;

import android.view.MotionEvent;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class A0 {
    public static final A0 a = new A0();

    public final boolean a(@NotNull MotionEvent motionEvent, int i) {
        float rawX = motionEvent.getRawX(i);
        if (Float.isInfinite(rawX) || Float.isNaN(rawX)) {
            return false;
        }
        float rawY = motionEvent.getRawY(i);
        return (Float.isInfinite(rawY) || Float.isNaN(rawY)) ? false : true;
    }
}
