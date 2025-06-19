package assistantMode.refactored.shims;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.StudiableData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final StudiableData a;
    public final boolean b;
    public final String c;

    public a(StudiableData studiableData, boolean z, String str) {
        Intrinsics.checkNotNullParameter(studiableData, "studiableData");
        this.a = studiableData;
        this.b = z;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iG + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Input(studiableData=");
        sb.append(this.a);
        sb.append(", skipTextClassification=");
        sb.append(this.b);
        sb.append(", userLanguageCode=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
