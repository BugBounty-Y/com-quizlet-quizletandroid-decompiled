package com.quizlet.features.infra.legacyadapter;

import android.view.View;
import android.view.ViewTreeObserver;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;

/* loaded from: classes3.dex */
public final class h implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ View b;
    public final /* synthetic */ Object c;

    public h(DiagramView diagramView, String str) {
        this.b = diagramView;
        this.c = str;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        switch (this.a) {
            case 0:
                View view = this.b;
                if (view.getHeight() != 0) {
                    view.getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    int[] iArr = new int[2];
                    view.getLocationInWindow(iArr);
                    ((RecyclerViewFragment) this.c).g.getLayoutParams().height = view.getHeight() - iArr[1];
                    break;
                }
                break;
            default:
                DiagramView diagramView = (DiagramView) this.b;
                if (diagramView.getWebView().getHeight() > 0) {
                    diagramView.c((String) this.c);
                    diagramView.getWebView().getViewTreeObserver().removeOnGlobalLayoutListener(this);
                    break;
                }
                break;
        }
    }

    public h(RecyclerViewFragment recyclerViewFragment, View view) {
        this.c = recyclerViewFragment;
        this.b = view;
    }
}
