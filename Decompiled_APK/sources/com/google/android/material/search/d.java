package com.google.android.material.search;

import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import androidx.core.view.H0;
import androidx.core.view.V;

/* loaded from: classes2.dex */
public final /* synthetic */ class d implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ SearchView b;

    public /* synthetic */ d(SearchView searchView, int i) {
        this.a = i;
        this.b = searchView;
    }

    @Override // java.lang.Runnable
    public final void run() {
        H0 h0H;
        H0 h0H2;
        switch (this.a) {
            case 0:
                SearchView searchView = this.b;
                EditText editText = searchView.j;
                if (editText.requestFocus()) {
                    editText.sendAccessibilityEvent(8);
                }
                if (searchView.z && (h0H = V.h(editText)) != null) {
                    h0H.a.e();
                    break;
                } else {
                    ((InputMethodManager) editText.getContext().getSystemService(InputMethodManager.class)).showSoftInput(editText, 1);
                    break;
                }
                break;
            case 1:
                SearchView searchView2 = this.b;
                EditText editText2 = searchView2.j;
                editText2.clearFocus();
                SearchBar searchBar = searchView2.t;
                if (searchBar != null) {
                    searchBar.requestFocus();
                }
                if (searchView2.z && (h0H2 = V.h(editText2)) != null) {
                    h0H2.a.a();
                    break;
                } else {
                    InputMethodManager inputMethodManager = (InputMethodManager) editText2.getContext().getSystemService(InputMethodManager.class);
                    if (inputMethodManager != null) {
                        inputMethodManager.hideSoftInputFromWindow(editText2.getWindowToken(), 0);
                        break;
                    }
                }
                break;
            case 2:
                this.b.k();
                break;
            default:
                this.b.i();
                break;
        }
    }
}
