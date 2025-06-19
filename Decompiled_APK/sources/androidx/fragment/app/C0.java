package androidx.fragment.app;

import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;

/* loaded from: classes.dex */
public final class C0 implements AdapterView.OnItemClickListener {
    public final /* synthetic */ D0 a;

    public C0(D0 d0) {
        this.a = d0;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        this.a.onListItemClick((ListView) adapterView, view, i, j);
    }
}
