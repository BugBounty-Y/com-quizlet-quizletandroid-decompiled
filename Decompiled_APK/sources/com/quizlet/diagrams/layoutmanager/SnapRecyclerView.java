package com.quizlet.diagrams.layoutmanager;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class SnapRecyclerView extends RecyclerView {
    public SnapRecyclerView(Context context) {
        super(context);
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public final boolean K(int i, int i2) {
        FlashCardsLayoutManager flashCardsLayoutManager = (FlashCardsLayoutManager) ((a) getLayoutManager());
        n0(flashCardsLayoutManager.v() != 0 ? flashCardsLayoutManager.p == 0 ? flashCardsLayoutManager.p1(i, flashCardsLayoutManager.u(0).getLeft(), flashCardsLayoutManager.u(0).getWidth(), AbstractC1381n0.K(flashCardsLayoutManager.u(0))) : flashCardsLayoutManager.p1(i2, flashCardsLayoutManager.u(0).getTop(), flashCardsLayoutManager.u(0).getHeight(), AbstractC1381n0.K(flashCardsLayoutManager.u(0))) : 0);
        return true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView, android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        boolean zOnTouchEvent = super.onTouchEvent(motionEvent);
        a aVar = (a) getLayoutManager();
        if (getScrollState() == 0 && (motionEvent.getActionMasked() == 1 || motionEvent.getActionMasked() == 3)) {
            n0(((FlashCardsLayoutManager) aVar).q1());
        }
        return zOnTouchEvent;
    }

    @Override // androidx.recyclerview.widget.RecyclerView
    public void setLayoutManager(AbstractC1381n0 abstractC1381n0) {
        if (!(abstractC1381n0 instanceof a) && !isInEditMode()) {
            throw new IllegalArgumentException("LayoutManager must implement ISnapLayoutManager");
        }
        super.setLayoutManager(abstractC1381n0);
    }

    public SnapRecyclerView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
