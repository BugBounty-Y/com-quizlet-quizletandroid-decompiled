package androidx.fragment.app;

import android.view.View;
import java.util.Objects;

/* loaded from: classes.dex */
public final class r implements androidx.lifecycle.Z {
    public final /* synthetic */ DialogInterfaceOnCancelListenerC1151t a;

    public r(DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t) {
        this.a = dialogInterfaceOnCancelListenerC1151t;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        if (((androidx.lifecycle.J) obj) != null) {
            DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t = this.a;
            if (dialogInterfaceOnCancelListenerC1151t.h) {
                View viewRequireView = dialogInterfaceOnCancelListenerC1151t.requireView();
                if (viewRequireView.getParent() != null) {
                    throw new IllegalStateException("DialogFragment can not be attached to a container view");
                }
                if (dialogInterfaceOnCancelListenerC1151t.l != null) {
                    if (AbstractC1136h0.N(3)) {
                        Objects.toString(dialogInterfaceOnCancelListenerC1151t.l);
                    }
                    dialogInterfaceOnCancelListenerC1151t.l.setContentView(viewRequireView);
                }
            }
        }
    }
}
