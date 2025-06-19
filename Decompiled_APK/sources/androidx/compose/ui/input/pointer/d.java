package androidx.compose.ui.input.pointer;

import android.view.MotionEvent;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class d {
    public static final d a = new d();

    public final long a(@NotNull MotionEvent motionEvent, int i) {
        return Q4.c(motionEvent.getRawX(i), motionEvent.getRawY(i));
    }
}
