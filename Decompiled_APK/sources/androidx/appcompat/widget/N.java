package androidx.appcompat.widget;

import android.view.ViewTreeObserver;
import android.widget.PopupWindow;
import androidx.appcompat.view.menu.ViewTreeObserverOnGlobalLayoutListenerC0067d;

/* loaded from: classes.dex */
public final class N implements PopupWindow.OnDismissListener {
    public final /* synthetic */ ViewTreeObserverOnGlobalLayoutListenerC0067d a;
    public final /* synthetic */ O b;

    public N(O o, ViewTreeObserverOnGlobalLayoutListenerC0067d viewTreeObserverOnGlobalLayoutListenerC0067d) {
        this.b = o;
        this.a = viewTreeObserverOnGlobalLayoutListenerC0067d;
    }

    @Override // android.widget.PopupWindow.OnDismissListener
    public final void onDismiss() {
        ViewTreeObserver viewTreeObserver = this.b.G.getViewTreeObserver();
        if (viewTreeObserver != null) {
            viewTreeObserver.removeGlobalOnLayoutListener(this.a);
        }
    }
}
