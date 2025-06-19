package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import androidx.compose.ui.text.C0995g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public final C0995g a;
    public C0995g b;
    public boolean c = false;
    public d d = null;

    public k(C0995g c0995g, C0995g c0995g2) {
        this.a = c0995g;
        this.b = c0995g2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && Intrinsics.b(this.b, kVar.b) && this.c == kVar.c && Intrinsics.b(this.d, kVar.d);
    }

    public final int hashCode() {
        int iG = d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
        d dVar = this.d;
        return iG + (dVar == null ? 0 : dVar.hashCode());
    }

    public final String toString() {
        return "TextSubstitutionValue(original=" + ((Object) this.a) + ", substitution=" + ((Object) this.b) + ", isShowingSubstitution=" + this.c + ", layoutCache=" + this.d + ')';
    }
}
