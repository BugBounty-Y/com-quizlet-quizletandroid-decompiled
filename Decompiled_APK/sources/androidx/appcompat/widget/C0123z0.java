package androidx.appcompat.widget;

import android.view.View;
import android.widget.AdapterView;

/* renamed from: androidx.appcompat.widget.z0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0123z0 implements AdapterView.OnItemSelectedListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0123z0(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a(AdapterView adapterView) {
    }

    private final void b(AdapterView adapterView) {
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public final void onItemSelected(AdapterView adapterView, View view, int i, long j) {
        C0113u0 c0113u0;
        switch (this.a) {
            case 0:
                if (i != -1 && (c0113u0 = ((G0) this.b).c) != null) {
                    c0113u0.setListSelectionHidden(false);
                    break;
                }
                break;
            default:
                ((SearchView) this.b).q(i);
                break;
        }
    }

    @Override // android.widget.AdapterView.OnItemSelectedListener
    public final void onNothingSelected(AdapterView adapterView) {
        int i = this.a;
    }
}
