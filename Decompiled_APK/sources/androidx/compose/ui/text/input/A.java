package androidx.compose.ui.text.input;

import androidx.compose.animation.d0;
import androidx.compose.ui.text.C0995g;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A {
    public static final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final C0995g a;
    public final long b;
    public final androidx.compose.ui.text.K c;

    static {
        z zVar = z.a;
        C1001d c1001d = C1001d.d;
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        d = new com.quizlet.data.repository.explanations.myexplanations.a(zVar, false, c1001d, 3);
    }

    public A(C0995g c0995g, long j, androidx.compose.ui.text.K k) {
        this.a = c0995g;
        this.b = AbstractC3205m5.f(c0995g.a.length(), j);
        this.c = k != null ? new androidx.compose.ui.text.K(AbstractC3205m5.f(c0995g.a.length(), k.a)) : null;
    }

    public static A a(A a, C0995g c0995g, long j, int i) {
        if ((i & 1) != 0) {
            c0995g = a.a;
        }
        if ((i & 2) != 0) {
            j = a.b;
        }
        androidx.compose.ui.text.K k = (i & 4) != 0 ? a.c : null;
        a.getClass();
        return new A(c0995g, j, k);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A)) {
            return false;
        }
        A a = (A) obj;
        return androidx.compose.ui.text.K.a(this.b, a.b) && Intrinsics.b(this.c, a.c) && Intrinsics.b(this.a, a.a);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        int i = androidx.compose.ui.text.K.c;
        int iD = d0.d(iHashCode, 31, this.b);
        androidx.compose.ui.text.K k = this.c;
        return iD + (k != null ? Long.hashCode(k.a) : 0);
    }

    public final String toString() {
        return "TextFieldValue(text='" + ((Object) this.a) + "', selection=" + ((Object) androidx.compose.ui.text.K.g(this.b)) + ", composition=" + this.c + ')';
    }

    public A(int i, long j, String str) {
        this(new C0995g(6, (i & 1) != 0 ? "" : str, null), (i & 2) != 0 ? androidx.compose.ui.text.K.b : j, (androidx.compose.ui.text.K) null);
    }
}
