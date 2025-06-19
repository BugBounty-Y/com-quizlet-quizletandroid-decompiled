package androidx.fragment.app;

import android.app.Dialog;
import android.content.DialogInterface;

/* renamed from: androidx.fragment.app.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class DialogInterfaceOnCancelListenerC1148p implements DialogInterface.OnCancelListener {
    public final /* synthetic */ DialogInterfaceOnCancelListenerC1151t a;

    public DialogInterfaceOnCancelListenerC1148p(DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t) {
        this.a = dialogInterfaceOnCancelListenerC1151t;
    }

    @Override // android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t = this.a;
        Dialog dialog = dialogInterfaceOnCancelListenerC1151t.l;
        if (dialog != null) {
            dialogInterfaceOnCancelListenerC1151t.onCancel(dialog);
        }
    }
}
