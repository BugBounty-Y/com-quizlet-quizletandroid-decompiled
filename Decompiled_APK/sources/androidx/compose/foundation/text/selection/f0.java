package androidx.compose.foundation.text.selection;

import androidx.collection.AbstractC0217o;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class f0 implements I {
    public final boolean a;
    public final int b;
    public final int c;
    public final C0536q d;
    public final C0534o e;

    public f0(boolean z, int i, int i2, C0536q c0536q, C0534o c0534o) {
        this.a = z;
        this.b = i;
        this.c = i2;
        this.d = c0536q;
        this.e = c0534o;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int a() {
        return 1;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final boolean b() {
        return this.a;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o c() {
        return this.e;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0536q d() {
        return this.d;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o e() {
        return this.e;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final androidx.collection.z f(C0536q c0536q) {
        boolean z = c0536q.c;
        C0535p c0535p = c0536q.b;
        C0535p c0535p2 = c0536q.a;
        if ((!z && c0535p2.b > c0535p.b) || (z && c0535p2.b <= c0535p.b)) {
            c0536q = C0536q.a(c0536q, null, null, !z, 3);
        }
        long j = this.e.a;
        androidx.collection.z zVar = AbstractC0217o.a;
        androidx.collection.z zVar2 = new androidx.collection.z();
        zVar2.f(j, c0536q);
        return zVar2;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final boolean g(I i) {
        if (this.d == null || i == null || !(i instanceof f0)) {
            return true;
        }
        f0 f0Var = (f0) i;
        if (this.b != f0Var.b || this.c != f0Var.c || this.a != f0Var.a) {
            return true;
        }
        C0534o c0534o = this.e;
        c0534o.getClass();
        C0534o c0534o2 = f0Var.e;
        return (c0534o.a == c0534o2.a && c0534o.c == c0534o2.c && c0534o.d == c0534o2.d) ? false : true;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int h() {
        return this.c;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o i() {
        return this.e;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int j() {
        int i = this.b;
        int i2 = this.c;
        if (i < i2) {
            return 2;
        }
        if (i > i2) {
            return 1;
        }
        return this.e.b();
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final void k(Function1 function1) {
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o l() {
        return this.e;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int m() {
        return this.b;
    }

    public final String toString() {
        return "SingleSelectionLayout(isStartHandle=" + this.a + ", crossed=" + androidx.compose.animation.d0.z(j()) + ", info=\n\t" + this.e + ')';
    }
}
