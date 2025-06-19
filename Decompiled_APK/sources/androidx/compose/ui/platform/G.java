package androidx.compose.ui.platform;

import android.view.View;
import android.view.ViewStructure;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class G {
    public static final G a = new G();

    public final void a(@NotNull ViewStructure viewStructure, @NotNull View view) {
        viewStructure.setClassName(view.getAccessibilityClassName().toString());
    }
}
