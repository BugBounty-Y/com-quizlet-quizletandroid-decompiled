package androidx.fragment.app;

import java.util.ArrayList;

/* renamed from: androidx.fragment.app.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1132f0 implements InterfaceC1130e0 {
    public final String a;
    public final int b;
    public final int c;
    public final /* synthetic */ AbstractC1136h0 d;

    public C1132f0(AbstractC1136h0 abstractC1136h0, String str, int i, int i2) {
        this.d = abstractC1136h0;
        this.a = str;
        this.b = i;
        this.c = i2;
    }

    @Override // androidx.fragment.app.InterfaceC1130e0
    public final boolean a(ArrayList arrayList, ArrayList arrayList2) {
        Fragment fragment = this.d.A;
        if (fragment == null || this.b >= 0 || this.a != null || !fragment.getChildFragmentManager().X(-1, 0)) {
            return this.d.Y(arrayList, arrayList2, this.a, this.b, this.c);
        }
        return false;
    }
}
