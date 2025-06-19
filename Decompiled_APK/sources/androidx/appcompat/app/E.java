package androidx.appcompat.app;

import android.app.Dialog;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;

/* loaded from: classes.dex */
public class E extends DialogInterfaceOnCancelListenerC1151t {
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public Dialog K(Bundle bundle) {
        return new D(getContext(), I());
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void N(Dialog dialog, int i) {
        if (!(dialog instanceof D)) {
            super.N(dialog, i);
            return;
        }
        D d = (D) dialog;
        if (i != 1 && i != 2) {
            if (i != 3) {
                return;
            } else {
                dialog.getWindow().addFlags(24);
            }
        }
        d.c().g(1);
    }
}
