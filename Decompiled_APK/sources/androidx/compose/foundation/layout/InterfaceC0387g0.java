package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.g0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC0387g0 extends C0 {
    @Override // androidx.compose.foundation.layout.C0
    default void a(int i, int[] iArr, int[] iArr2, androidx.compose.ui.layout.M m) {
        if (i()) {
            g().c(m, i, iArr, m.getLayoutDirection(), iArr2);
        } else {
            h().b(m, i, iArr, iArr2);
        }
    }

    @Override // androidx.compose.foundation.layout.C0
    default androidx.compose.ui.layout.L b(androidx.compose.ui.layout.W[] wArr, androidx.compose.ui.layout.M m, int i, int[] iArr, int i2, int i3, int[] iArr2, int i4, int i5, int i6) {
        int i7;
        int i8;
        if (i()) {
            i8 = i2;
            i7 = i3;
        } else {
            i7 = i2;
            i8 = i3;
        }
        return m.n0(i8, i7, kotlin.collections.V.c(), new C0385f0(iArr2, i4, i5, i6, wArr, this, i3, m, i, iArr));
    }

    @Override // androidx.compose.foundation.layout.C0
    default int c(androidx.compose.ui.layout.W w) {
        return i() ? w.k0() : w.i0();
    }

    @Override // androidx.compose.foundation.layout.C0
    default long d(boolean z, int i, int i2, int i3) {
        return i() ? E0.a(z, i, i2, i3) : A.b(z, i, i2, i3);
    }

    @Override // androidx.compose.foundation.layout.C0
    default int e(androidx.compose.ui.layout.W w) {
        return i() ? w.i0() : w.k0();
    }

    AbstractC0382e f();

    InterfaceC0388h g();

    InterfaceC0394k h();

    boolean i();
}
