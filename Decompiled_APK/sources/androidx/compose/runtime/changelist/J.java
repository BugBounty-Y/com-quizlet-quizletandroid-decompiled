package androidx.compose.runtime.changelist;

import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;

/* loaded from: classes.dex */
public abstract class J {
    public final int a;
    public final int b;

    public J(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public abstract void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar);

    public final String toString() {
        String strF = kotlin.jvm.internal.K.a(getClass()).f();
        return strF == null ? "" : strF;
    }

    public /* synthetic */ J(int i, int i2, int i3) {
        this((i3 & 1) != 0 ? 0 : i, (i3 & 2) != 0 ? 0 : i2);
    }
}
