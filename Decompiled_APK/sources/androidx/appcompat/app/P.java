package androidx.appcompat.app;

import android.view.View;
import androidx.appcompat.widget.ActionBarOverlayLayout;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3267t6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class P extends AbstractC3267t6 {
    public final /* synthetic */ int b;
    public final /* synthetic */ T c;

    public /* synthetic */ P(T t, int i) {
        this.b = i;
        this.c = t;
    }

    @Override // androidx.core.view.InterfaceC1045e0
    public final void c() {
        View view;
        T t = this.c;
        switch (this.b) {
            case 0:
                if (t.o && (view = t.g) != null) {
                    view.setTranslationY(DefinitionKt.NO_Float_VALUE);
                    t.d.setTranslationY(DefinitionKt.NO_Float_VALUE);
                }
                t.d.setVisibility(8);
                t.d.setTransitioning(false);
                t.t = null;
                androidx.compose.foundation.text.input.internal.u uVar = t.k;
                if (uVar != null) {
                    uVar.l(t.j);
                    t.j = null;
                    t.k = null;
                }
                ActionBarOverlayLayout actionBarOverlayLayout = t.c;
                if (actionBarOverlayLayout != null) {
                    WeakHashMap weakHashMap = V.a;
                    androidx.core.view.J.c(actionBarOverlayLayout);
                    break;
                }
                break;
            default:
                t.t = null;
                t.d.requestLayout();
                break;
        }
    }
}
