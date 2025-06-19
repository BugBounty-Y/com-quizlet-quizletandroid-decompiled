package com.google.android.material.search;

import android.view.View;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ SearchView b;

    public /* synthetic */ c(SearchView searchView, int i) {
        this.a = i;
        this.b = searchView;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        SearchView searchView = this.b;
        switch (this.a) {
            case 0:
                searchView.j.setText("");
                searchView.i();
                break;
            case 1:
                int i = SearchView.D;
                searchView.k();
                break;
            default:
                int i2 = SearchView.D;
                if (!searchView.B.equals(h.b) && !searchView.B.equals(h.a)) {
                    searchView.o.k();
                    break;
                }
                break;
        }
    }
}
