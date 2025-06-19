package androidx.compose.foundation.text.input.internal;

import android.view.View;
import android.view.inputmethod.InputMethodManager;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class i {
    public static final i a = new i();

    public final void a(@NotNull InputMethodManager inputMethodManager, @NotNull View view) {
        inputMethodManager.startStylusHandwriting(view);
    }
}
