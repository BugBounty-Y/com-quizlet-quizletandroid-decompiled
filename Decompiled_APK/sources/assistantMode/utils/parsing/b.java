package assistantMode.utils.parsing;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final String a;
    public final boolean b;

    public b(String text, boolean z) {
        Intrinsics.checkNotNullParameter("", "tag");
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        bVar.getClass();
        return this.a.equals(bVar.a) && this.b == bVar.b;
    }

    public final int hashCode() {
        return d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Option(tag=, text=");
        sb.append(this.a);
        sb.append(", isCorrect=");
        return android.support.v4.media.session.a.o(", explanation=null)", sb, this.b);
    }
}
