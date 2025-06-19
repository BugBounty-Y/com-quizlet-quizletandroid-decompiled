package androidx.compose.ui.node;

import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;

/* loaded from: classes.dex */
public abstract class H {
    public static final androidx.compose.ui.unit.c a = M5.b();

    public static final g0 a(E e) {
        C0971v c0971v = e.i;
        if (c0971v != null) {
            return c0971v;
        }
        W4.g("LayoutNode should be attached to an owner");
        throw null;
    }
}
