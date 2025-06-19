package androidx.compose.ui.platform;

import android.R;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3133e5;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0979z {
    public static final void a(@NotNull androidx.core.view.accessibility.e eVar, @NotNull androidx.compose.ui.semantics.o oVar) {
        if (N.l(oVar)) {
            androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.a;
            androidx.compose.ui.semantics.u uVar2 = androidx.compose.ui.semantics.j.w;
            androidx.compose.ui.semantics.k kVar = oVar.d;
            androidx.compose.ui.semantics.a aVar = (androidx.compose.ui.semantics.a) AbstractC3133e5.d(kVar, uVar2);
            if (aVar != null) {
                eVar.b(new androidx.core.view.accessibility.d(R.id.accessibilityActionPageUp, aVar.a));
            }
            androidx.compose.ui.semantics.a aVar2 = (androidx.compose.ui.semantics.a) AbstractC3133e5.d(kVar, androidx.compose.ui.semantics.j.y);
            if (aVar2 != null) {
                eVar.b(new androidx.core.view.accessibility.d(R.id.accessibilityActionPageDown, aVar2.a));
            }
            androidx.compose.ui.semantics.a aVar3 = (androidx.compose.ui.semantics.a) AbstractC3133e5.d(kVar, androidx.compose.ui.semantics.j.x);
            if (aVar3 != null) {
                eVar.b(new androidx.core.view.accessibility.d(R.id.accessibilityActionPageLeft, aVar3.a));
            }
            androidx.compose.ui.semantics.a aVar4 = (androidx.compose.ui.semantics.a) AbstractC3133e5.d(kVar, androidx.compose.ui.semantics.j.z);
            if (aVar4 != null) {
                eVar.b(new androidx.core.view.accessibility.d(R.id.accessibilityActionPageRight, aVar4.a));
            }
        }
    }
}
