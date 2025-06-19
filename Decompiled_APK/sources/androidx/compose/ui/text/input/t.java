package androidx.compose.ui.text.input;

import androidx.compose.ui.text.C0995g;

/* loaded from: classes.dex */
public final class t implements K {
    @Override // androidx.compose.ui.text.input.K
    public final I e(C0995g c0995g) {
        return new I(new C0995g(6, kotlin.text.D.n(c0995g.a.length(), String.valueOf((char) 8226)), null), r.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof t)) {
            return false;
        }
        ((t) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return Character.hashCode((char) 8226);
    }
}
