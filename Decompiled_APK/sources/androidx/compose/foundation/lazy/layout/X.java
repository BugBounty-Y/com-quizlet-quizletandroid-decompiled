package androidx.compose.foundation.lazy.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class X implements W0 {
    public final int a;
    public final int b;
    public final InterfaceC0773a0 c;
    public int d;

    public X(int i, int i2, int i3) {
        this.a = i2;
        this.b = i3;
        int i4 = (i / i2) * i2;
        this.c = C0776c.y(kotlin.ranges.l.h(Math.max(i4 - i3, 0), i4 + i2 + i3), androidx.compose.runtime.V.f);
        this.d = i;
    }

    public final void a(int i) {
        if (i != this.d) {
            this.d = i;
            int i2 = this.a;
            int i3 = (i / i2) * i2;
            int i4 = this.b;
            ((L0) this.c).setValue(kotlin.ranges.l.h(Math.max(i3 - i4, 0), i3 + i2 + i4));
        }
    }

    @Override // androidx.compose.runtime.W0
    public final Object getValue() {
        return (IntRange) ((L0) this.c).getValue();
    }
}
