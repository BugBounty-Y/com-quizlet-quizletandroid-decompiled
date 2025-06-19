package androidx.compose.ui.text.input;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public static final m g = new m(false, 0, true, 1, 1, androidx.compose.ui.text.intl.b.c);
    public final boolean a;
    public final int b;
    public final boolean c;
    public final int d;
    public final int e;
    public final androidx.compose.ui.text.intl.b f;

    public m(boolean z, int i, boolean z2, int i2, int i3, androidx.compose.ui.text.intl.b bVar) {
        this.a = z;
        this.b = i;
        this.c = z2;
        this.d = i2;
        this.e = i3;
        this.f = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        if (this.a != mVar.a) {
            return false;
        }
        if (this.b != mVar.b || this.c != mVar.c) {
            return false;
        }
        if (this.d == mVar.d) {
            if (this.e == mVar.e) {
                mVar.getClass();
                return Intrinsics.b(this.f, mVar.f);
            }
        }
        return false;
    }

    public final int hashCode() {
        return this.f.a.hashCode() + d0.b(this.e, d0.b(this.d, d0.g(d0.b(this.b, Boolean.hashCode(this.a) * 31, 31), 31, this.c), 31), 961);
    }

    public final String toString() {
        return "ImeOptions(singleLine=" + this.a + ", capitalization=" + ((Object) n.a(this.b)) + ", autoCorrect=" + this.c + ", keyboardType=" + ((Object) o.a(this.d)) + ", imeAction=" + ((Object) l.a(this.e)) + ", platformImeOptions=null, hintLocales=" + this.f + ')';
    }
}
