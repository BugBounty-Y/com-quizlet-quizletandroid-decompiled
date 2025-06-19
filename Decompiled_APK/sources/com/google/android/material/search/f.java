package com.google.android.material.search;

import android.view.View;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.internal.p;
import com.google.android.material.internal.s;

/* loaded from: classes2.dex */
public final /* synthetic */ class f implements s, InterfaceC1062t {
    public final /* synthetic */ SearchView a;

    public /* synthetic */ f(SearchView searchView) {
        this.a = searchView;
    }

    @Override // com.google.android.material.internal.s
    public D0 k(View view, D0 d0, com.google.android.gms.ads.internal.overlay.k kVar) {
        MaterialToolbar materialToolbar = this.a.g;
        boolean zK = p.k(materialToolbar);
        materialToolbar.setPadding(d0.b() + (zK ? kVar.c : kVar.a), kVar.b, d0.c() + (zK ? kVar.a : kVar.c), kVar.d);
        return d0;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        SearchView.e(this.a, d0);
        return d0;
    }
}
