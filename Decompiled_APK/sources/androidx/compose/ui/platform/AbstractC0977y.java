package androidx.compose.ui.platform;

import android.R;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0977y {
    public static final void a(@NotNull androidx.core.view.accessibility.e eVar, @NotNull androidx.compose.ui.semantics.o oVar) {
        if (N.l(oVar)) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.a;
            androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) AbstractC3133e5.d(oVar.d, androidx.compose.ui.semantics.j.g);
            if (aVar != null) {
                eVar.b(new androidx.core.view.accessibility.d(R.id.accessibilityActionSetProgress, aVar.a));
            }
        }
    }
}
