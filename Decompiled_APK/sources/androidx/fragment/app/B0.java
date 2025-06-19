package androidx.fragment.app;

import android.widget.ListView;

/* loaded from: classes.dex */
public final class B0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ B0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ListView listView = ((D0) this.b).mList;
                listView.focusableViewAvailable(listView);
                break;
            case 1:
                DialogInterfaceOnCancelListenerC1151t dialogInterfaceOnCancelListenerC1151t = (DialogInterfaceOnCancelListenerC1151t) this.b;
                dialogInterfaceOnCancelListenerC1151t.d.onDismiss(dialogInterfaceOnCancelListenerC1151t.l);
                break;
            case 2:
                ((Fragment) this.b).startPostponedEnterTransition();
                break;
            default:
                ((AbstractC1136h0) this.b).A(true);
                break;
        }
    }
}
