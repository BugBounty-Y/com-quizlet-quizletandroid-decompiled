package androidx.compose.ui.platform;

import android.view.PointerIcon;
import android.view.View;
import androidx.compose.ui.input.pointer.C0878a;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class L {
    public static final L a = new L();

    public final void a(@NotNull View view, androidx.compose.ui.input.pointer.j jVar) {
        PointerIcon systemIcon = jVar instanceof C0878a ? PointerIcon.getSystemIcon(view.getContext(), ((C0878a) jVar).b) : PointerIcon.getSystemIcon(view.getContext(), 1000);
        if (Intrinsics.b(view.getPointerIcon(), systemIcon)) {
            return;
        }
        view.setPointerIcon(systemIcon);
    }
}
