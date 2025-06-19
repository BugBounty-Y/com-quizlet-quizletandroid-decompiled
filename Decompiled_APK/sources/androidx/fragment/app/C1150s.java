package androidx.fragment.app;

import android.app.Dialog;
import android.view.View;

/* renamed from: androidx.fragment.app.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1150s extends L {
    public final /* synthetic */ L a;
    public final /* synthetic */ DialogInterfaceOnCancelListenerC1151t b;

    public C1150s(DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t, L l) {
        this.b = dialogInterfaceOnCancelListenerC1151t;
        this.a = l;
    }

    @Override // androidx.fragment.app.L
    public final View b(int i) {
        L l = this.a;
        if (l.c()) {
            return l.b(i);
        }
        Dialog dialog = this.b.l;
        if (dialog != null) {
            return dialog.findViewById(i);
        }
        return null;
    }

    @Override // androidx.fragment.app.L
    public final boolean c() {
        return this.a.c() || this.b.p;
    }
}
