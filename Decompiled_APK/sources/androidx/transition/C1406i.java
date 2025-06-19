package androidx.transition;

import android.view.View;
import java.util.ArrayList;

/* renamed from: androidx.transition.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1406i implements InterfaceC1419w {
    public final /* synthetic */ View a;
    public final /* synthetic */ ArrayList b;

    public C1406i(View view, ArrayList arrayList) {
        this.a = view;
        this.b = arrayList;
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void a() {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void b(y yVar) {
        yVar.D(this);
        yVar.b(this);
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
        yVar.D(this);
        this.a.setVisibility(8);
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((View) arrayList.get(i)).setVisibility(0);
        }
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void f(y yVar) {
    }

    @Override // androidx.transition.InterfaceC1419w
    public final void g() {
    }
}
