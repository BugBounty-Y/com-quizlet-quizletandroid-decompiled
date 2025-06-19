package com.google.android.material.bottomsheet;

import android.app.Dialog;
import android.os.Bundle;
import androidx.appcompat.app.E;

/* loaded from: classes2.dex */
public class i extends E {
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void G() {
        P();
        H(false, false);
    }

    @Override // androidx.appcompat.app.E, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public Dialog K(Bundle bundle) {
        return new h(getContext(), I());
    }

    public final void P() {
        Dialog dialog = this.l;
        if (dialog instanceof h) {
            boolean z = ((h) dialog).g().I;
        }
    }
}
