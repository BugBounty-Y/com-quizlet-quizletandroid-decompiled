package androidx.compose.foundation.text.modifiers;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n {
    public final String a;
    public String b;
    public boolean c = false;
    public e d = null;

    public n(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b) && this.c == nVar.c && Intrinsics.b(this.d, nVar.d);
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        e eVar = this.d;
        return iG + (eVar == null ? 0 : eVar.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextSubstitution(layoutCache=");
        sb.append(this.d);
        sb.append(", isShowingSubstitution=");
        return android.support.v4.media.session.a.u(sb, this.c, ')');
    }
}
