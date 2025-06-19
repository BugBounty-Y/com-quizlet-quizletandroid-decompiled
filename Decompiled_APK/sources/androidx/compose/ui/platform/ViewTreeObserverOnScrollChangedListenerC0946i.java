package androidx.compose.ui.platform;

import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class ViewTreeObserverOnScrollChangedListenerC0946i implements ViewTreeObserver.OnScrollChangedListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ ViewGroup b;

    public /* synthetic */ ViewTreeObserverOnScrollChangedListenerC0946i(ViewGroup viewGroup, int i) {
        this.a = i;
        this.b = viewGroup;
    }

    @Override // android.view.ViewTreeObserver.OnScrollChangedListener
    public final void onScrollChanged() {
        ViewGroup viewGroup = this.b;
        switch (this.a) {
            case 0:
                ((C0971v) viewGroup).G();
                break;
            default:
                int i = com.amazon.aps.ads.util.adview.b.a;
                com.amazon.aps.ads.util.adview.b this$0 = (com.amazon.aps.ads.util.adview.b) viewGroup;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.verifyIsVisible();
                break;
        }
    }
}
