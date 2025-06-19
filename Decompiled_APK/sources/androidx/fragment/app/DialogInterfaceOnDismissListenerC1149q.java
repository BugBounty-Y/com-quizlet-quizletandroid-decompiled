package androidx.fragment.app;

import android.app.Dialog;
import android.content.DialogInterface;

/* renamed from: androidx.fragment.app.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class DialogInterfaceOnDismissListenerC1149q implements DialogInterface.OnDismissListener {
    public final /* synthetic */ DialogInterfaceOnCancelListenerC1151t a;

    public DialogInterfaceOnDismissListenerC1149q(DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t) {
        this.a = dialogInterfaceOnCancelListenerC1151t;
    }

    @Override // android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialogInterface) {
        DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t = this.a;
        Dialog dialog = dialogInterfaceOnCancelListenerC1151t.l;
        if (dialog != null) {
            dialogInterfaceOnCancelListenerC1151t.onDismiss(dialog);
        }
    }
}
