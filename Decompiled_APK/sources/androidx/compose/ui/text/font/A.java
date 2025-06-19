package androidx.compose.ui.text.font;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A {
    public final int a;
    public final u b;
    public final t c;

    public A(int i, u uVar, t tVar) {
        this.a = i;
        this.b = uVar;
        this.c = tVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A)) {
            return false;
        }
        A a = (A) obj;
        return this.a == a.a && Intrinsics.b(this.b, a.b) && this.c.equals(a.c);
    }

    public final int hashCode() {
        return this.c.a.hashCode() + d0.b(0, d0.b(0, ((this.a * 31) + this.b.a) * 31, 31), 31);
    }

    public final String toString() {
        return "ResourceFont(resId=" + this.a + ", weight=" + this.b + ", style=" + ((Object) "Normal") + ", loadingStrategy=Blocking)";
    }
}
