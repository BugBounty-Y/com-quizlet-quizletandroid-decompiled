package androidx.compose.ui.platform;

import android.view.ViewParent;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class u1 {
    public static final u1 a = new u1();

    public final void a(@NotNull C0971v c0971v) {
        ViewParent parent = c0971v.getParent();
        if (parent != null) {
            parent.onDescendantInvalidated(c0971v, c0971v);
        }
    }
}
