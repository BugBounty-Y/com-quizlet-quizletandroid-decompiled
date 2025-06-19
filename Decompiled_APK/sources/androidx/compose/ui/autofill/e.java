package androidx.compose.ui.autofill;

import android.view.autofill.AutofillManager;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class e extends AutofillManager.AutofillCallback {
    public static final e a = new e();

    public final void a(@NotNull a aVar) {
        aVar.c.registerCallback(this);
    }

    public final void b(@NotNull a aVar) {
        aVar.c.unregisterCallback(this);
    }
}
