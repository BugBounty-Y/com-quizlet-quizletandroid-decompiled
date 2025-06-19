package androidx.appcompat.view.menu;

import android.R;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

/* loaded from: classes.dex */
public final class ExpandedMenuView extends ListView implements m, B, AdapterView.OnItemClickListener {
    public static final int[] b = {R.attr.background, R.attr.divider};
    public n a;

    public ExpandedMenuView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        setOnItemClickListener(this);
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, attributeSet, b, R.attr.listViewStyle);
        TypedArray typedArray = (TypedArray) eVarM.c;
        if (typedArray.hasValue(0)) {
            setBackgroundDrawable(eVarM.f(0));
        }
        if (typedArray.hasValue(1)) {
            setDivider(eVarM.f(1));
        }
        eVarM.n();
    }

    @Override // androidx.appcompat.view.menu.m
    public final boolean a(p pVar) {
        return this.a.q(pVar, null, 0);
    }

    @Override // androidx.appcompat.view.menu.B
    public final void b(n nVar) {
        this.a = nVar;
    }

    public int getWindowAnimations() {
        return 0;
    }

    @Override // android.widget.ListView, android.widget.AbsListView, android.widget.AdapterView, android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        setChildrenDrawingCacheEnabled(false);
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        a((p) getAdapter().getItem(i));
    }
}
