package androidx.appcompat.widget;

import android.view.View;

/* loaded from: classes.dex */
public final class W0 implements View.OnFocusChangeListener {
    public final /* synthetic */ SearchView a;

    public W0(SearchView searchView) {
        this.a = searchView;
    }

    @Override // android.view.View.OnFocusChangeListener
    public final void onFocusChange(View view, boolean z) {
        SearchView searchView = this.a;
        View.OnFocusChangeListener onFocusChangeListener = searchView.M;
        if (onFocusChangeListener != null) {
            onFocusChangeListener.onFocusChange(searchView, z);
        }
    }
}
