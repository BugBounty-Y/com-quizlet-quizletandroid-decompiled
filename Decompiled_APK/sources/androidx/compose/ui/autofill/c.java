package androidx.compose.ui.autofill;

import android.view.ViewStructure;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();

    public final int a(@NotNull ViewStructure viewStructure, int i) {
        return viewStructure.addChildCount(i);
    }

    public final ViewStructure b(@NotNull ViewStructure viewStructure, int i) {
        return viewStructure.newChild(i);
    }

    public final void c(@NotNull ViewStructure viewStructure, int i, int i2, int i3, int i4, int i5, int i6) {
        viewStructure.setDimens(i, i2, i3, i4, i5, i6);
    }

    public final void d(@NotNull ViewStructure viewStructure, int i, String str, String str2, String str3) {
        viewStructure.setId(i, str, str2, str3);
    }
}
