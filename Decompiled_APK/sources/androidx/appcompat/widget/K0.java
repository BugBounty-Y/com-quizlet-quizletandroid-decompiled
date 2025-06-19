package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.widget.HeaderViewListAdapter;
import android.widget.ListAdapter;
import androidx.appcompat.view.menu.ListMenuItemView;

/* loaded from: classes.dex */
public final class K0 extends C0113u0 {
    public final int m;
    public final int n;
    public H0 o;
    public androidx.appcompat.view.menu.p p;

    public K0(Context context, boolean z) {
        super(context, z);
        if (1 == context.getResources().getConfiguration().getLayoutDirection()) {
            this.m = 21;
            this.n = 22;
        } else {
            this.m = 22;
            this.n = 21;
        }
    }

    @Override // androidx.appcompat.widget.C0113u0, android.view.View
    public final boolean onHoverEvent(MotionEvent motionEvent) {
        androidx.appcompat.view.menu.k kVar;
        int headersCount;
        int iPointToPosition;
        int i;
        if (this.o != null) {
            ListAdapter adapter = getAdapter();
            if (adapter instanceof HeaderViewListAdapter) {
                HeaderViewListAdapter headerViewListAdapter = (HeaderViewListAdapter) adapter;
                headersCount = headerViewListAdapter.getHeadersCount();
                kVar = (androidx.appcompat.view.menu.k) headerViewListAdapter.getWrappedAdapter();
            } else {
                kVar = (androidx.appcompat.view.menu.k) adapter;
                headersCount = 0;
            }
            androidx.appcompat.view.menu.p pVarB = (motionEvent.getAction() == 10 || (iPointToPosition = pointToPosition((int) motionEvent.getX(), (int) motionEvent.getY())) == -1 || (i = iPointToPosition - headersCount) < 0 || i >= kVar.getCount()) ? null : kVar.getItem(i);
            androidx.appcompat.view.menu.p pVar = this.p;
            if (pVar != pVarB) {
                androidx.appcompat.view.menu.n nVar = kVar.a;
                if (pVar != null) {
                    this.o.o(nVar, pVar);
                }
                this.p = pVarB;
                if (pVarB != null) {
                    this.o.c(nVar, pVarB);
                }
            }
        }
        return super.onHoverEvent(motionEvent);
    }

    @Override // android.widget.ListView, android.widget.AbsListView, android.view.View, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent keyEvent) {
        ListMenuItemView listMenuItemView = (ListMenuItemView) getSelectedView();
        if (listMenuItemView != null && i == this.m) {
            if (listMenuItemView.isEnabled() && listMenuItemView.getItemData().hasSubMenu()) {
                performItemClick(listMenuItemView, getSelectedItemPosition(), getSelectedItemId());
            }
            return true;
        }
        if (listMenuItemView == null || i != this.n) {
            return super.onKeyDown(i, keyEvent);
        }
        setSelection(-1);
        ListAdapter adapter = getAdapter();
        (adapter instanceof HeaderViewListAdapter ? (androidx.appcompat.view.menu.k) ((HeaderViewListAdapter) adapter).getWrappedAdapter() : (androidx.appcompat.view.menu.k) adapter).a.c(false);
        return true;
    }

    public void setHoverListener(H0 h0) {
        this.o = h0;
    }

    @Override // androidx.appcompat.widget.C0113u0, android.widget.AbsListView
    public /* bridge */ /* synthetic */ void setSelector(Drawable drawable) {
        super.setSelector(drawable);
    }
}
