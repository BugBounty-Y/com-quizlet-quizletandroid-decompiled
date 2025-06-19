package androidx.transition;

import java.util.ArrayList;

/* renamed from: androidx.transition.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1407j extends z {
    public final /* synthetic */ Object a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ ArrayList d;
    public final /* synthetic */ C1409l e;

    public C1407j(C1409l c1409l, Object obj, ArrayList arrayList, Object obj2, ArrayList arrayList2) {
        this.e = c1409l;
        this.a = obj;
        this.b = arrayList;
        this.c = obj2;
        this.d = arrayList2;
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void b(y yVar) {
        C1409l c1409l = this.e;
        Object obj = this.a;
        if (obj != null) {
            c1409l.z(obj, this.b, null);
        }
        Object obj2 = this.c;
        if (obj2 != null) {
            c1409l.z(obj2, this.d, null);
        }
    }

    @Override // androidx.transition.z, androidx.transition.InterfaceC1419w
    public final void d(y yVar) {
        yVar.D(this);
    }
}
