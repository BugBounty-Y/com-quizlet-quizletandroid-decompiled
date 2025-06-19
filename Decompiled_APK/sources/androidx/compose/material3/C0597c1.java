package androidx.compose.material3;

import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0877z;
import androidx.compose.ui.node.AbstractC0910f;

/* renamed from: androidx.compose.material3.c1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0597c1 implements InterfaceC0877z {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0597c1(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0877z
    public final long a() {
        switch (this.a) {
            case 0:
                C0609e1 c0609e1 = (C0609e1) this.b;
                long jA = c0609e1.s.a();
                if (jA != 16) {
                    return jA;
                }
                C0690n3 c0690n3 = (C0690n3) AbstractC0910f.i(c0609e1, AbstractC0696o3.b);
                if (c0690n3 != null) {
                    long j = c0690n3.a;
                    if (j != 16) {
                        return j;
                    }
                }
                return ((C0861v) AbstractC0910f.i(c0609e1, AbstractC0669k0.a)).a;
            default:
                return ((C0702p3) this.b).c;
        }
    }
}
