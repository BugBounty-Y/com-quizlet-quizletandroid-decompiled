package androidx.compose.ui.layout;

/* renamed from: androidx.compose.ui.layout.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0890k implements J {
    public final /* synthetic */ int a;
    public final J b;
    public final int c;
    public final int d;

    public /* synthetic */ C0890k(J j, int i, int i2, int i3) {
        this.a = i3;
        this.b = j;
        this.c = i;
        this.d = i2;
    }

    @Override // androidx.compose.ui.layout.J
    public final W B(long j) {
        switch (this.a) {
            case 0:
                int i = this.d;
                int i2 = this.c;
                J j2 = this.b;
                if (i == 1) {
                    return new C0892m(i2 == 2 ? j2.z(androidx.compose.ui.unit.a.g(j)) : j2.x(androidx.compose.ui.unit.a.g(j)), androidx.compose.ui.unit.a.c(j) ? androidx.compose.ui.unit.a.g(j) : 32767, 0);
                }
                return new C0892m(androidx.compose.ui.unit.a.d(j) ? androidx.compose.ui.unit.a.h(j) : 32767, i2 == 2 ? j2.b(androidx.compose.ui.unit.a.h(j)) : j2.X(androidx.compose.ui.unit.a.h(j)), 0);
            case 1:
                int i3 = this.d;
                int i4 = this.c;
                J j3 = this.b;
                if (i3 == 1) {
                    return new C0892m(i4 == 2 ? j3.z(androidx.compose.ui.unit.a.g(j)) : j3.x(androidx.compose.ui.unit.a.g(j)), androidx.compose.ui.unit.a.c(j) ? androidx.compose.ui.unit.a.g(j) : 32767, 1);
                }
                return new C0892m(androidx.compose.ui.unit.a.d(j) ? androidx.compose.ui.unit.a.h(j) : 32767, i4 == 2 ? j3.b(androidx.compose.ui.unit.a.h(j)) : j3.X(androidx.compose.ui.unit.a.h(j)), 1);
            default:
                int i5 = this.d;
                int i6 = this.c;
                J j4 = this.b;
                if (i5 == 1) {
                    return new C0892m(i6 == 2 ? j4.z(androidx.compose.ui.unit.a.g(j)) : j4.x(androidx.compose.ui.unit.a.g(j)), androidx.compose.ui.unit.a.c(j) ? androidx.compose.ui.unit.a.g(j) : 32767, 2);
                }
                return new C0892m(androidx.compose.ui.unit.a.d(j) ? androidx.compose.ui.unit.a.h(j) : 32767, i6 == 2 ? j4.b(androidx.compose.ui.unit.a.h(j)) : j4.X(androidx.compose.ui.unit.a.h(j)), 2);
        }
    }

    @Override // androidx.compose.ui.layout.J
    public final Object G() {
        switch (this.a) {
        }
        return this.b.G();
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        switch (this.a) {
        }
        return this.b.X(i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        switch (this.a) {
        }
        return this.b.b(i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        switch (this.a) {
        }
        return this.b.x(i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        switch (this.a) {
        }
        return this.b.z(i);
    }
}
