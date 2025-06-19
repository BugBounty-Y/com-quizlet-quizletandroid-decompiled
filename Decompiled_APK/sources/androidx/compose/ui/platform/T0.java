package androidx.compose.ui.platform;

import android.view.ActionMode;
import android.view.View;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class T0 {
    public static final T0 a = new T0();

    public final void a(@NotNull ActionMode actionMode) {
        actionMode.invalidateContentRect();
    }

    public final ActionMode b(@NotNull View view, @NotNull ActionMode.Callback callback, int i) {
        return view.startActionMode(callback, i);
    }
}
