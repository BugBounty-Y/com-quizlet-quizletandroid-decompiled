package androidx.compose.ui.graphics;

import android.graphics.Shader;

/* loaded from: classes.dex */
public final class X extends AbstractC0857q {
    public final long a;

    public X(long j) {
        this.a = j;
    }

    @Override // androidx.compose.ui.graphics.AbstractC0857q
    public final void a(float f, long j, com.google.android.gms.cloudmessaging.k kVar) {
        kVar.d(1.0f);
        long jB = this.a;
        if (f != 1.0f) {
            jB = C0861v.b(jB, C0861v.d(jB) * f);
        }
        kVar.f(jB);
        if (((Shader) kVar.d) != null) {
            kVar.i(null);
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof X) {
            return C0861v.c(this.a, ((X) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return "SolidColor(value=" + ((Object) C0861v.i(this.a)) + ')';
    }
}
