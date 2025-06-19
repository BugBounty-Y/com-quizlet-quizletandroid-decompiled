package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;

/* loaded from: classes.dex */
public final class J implements W0 {
    public Number a;
    public Number b;
    public final L0 c;
    public final InterfaceC0773a0 d;
    public C0270u0 e;
    public boolean f;
    public boolean g;
    public long h;
    public final /* synthetic */ N i;

    public J(N n, Number number, Number number2, L0 l0, I i) {
        this.i = n;
        this.a = number;
        this.b = number2;
        this.c = l0;
        this.d = C0776c.z(number);
        this.e = new C0270u0(i, l0, this.a, this.b, null);
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return ((androidx.compose.runtime.L0) this.d).getValue();
    }
}
