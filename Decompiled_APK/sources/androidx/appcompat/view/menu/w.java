package androidx.appcompat.view.menu;

import android.widget.PopupWindow;

/* loaded from: classes.dex */
public final class w implements PopupWindow.OnDismissListener {
    public final /* synthetic */ x a;

    public w(x xVar) {
        this.a = xVar;
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public final void onDismiss() {
        this.a.c();
    }
}
