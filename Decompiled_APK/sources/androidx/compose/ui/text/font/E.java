package androidx.compose.ui.text.font;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class E {
    public final j a;
    public final u b;
    public final int c;
    public final int d;
    public final Object e;

    public E(j jVar, u uVar, int i, int i2, Object obj) {
        this.a = jVar;
        this.b = uVar;
        this.c = i;
        this.d = i2;
        this.e = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof E)) {
            return false;
        }
        E e = (E) obj;
        return Intrinsics.b(this.a, e.a) && Intrinsics.b(this.b, e.b) && this.c == e.c && this.d == e.d && Intrinsics.b(this.e, e.e);
    }

    public final int hashCode() {
        j jVar = this.a;
        int iB = d0.b(this.d, d0.b(this.c, (((jVar == null ? 0 : jVar.hashCode()) * 31) + this.b.a) * 31, 31), 31);
        Object obj = this.e;
        return iB + (obj != null ? obj.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TypefaceRequest(fontFamily=");
        sb.append(this.a);
        sb.append(", fontWeight=");
        sb.append(this.b);
        sb.append(", fontStyle=");
        String str = "Invalid";
        int i = this.c;
        sb.append((Object) (i == 0 ? "Normal" : i == 1 ? "Italic" : "Invalid"));
        sb.append(", fontSynthesis=");
        int i2 = this.d;
        if (i2 == 0) {
            str = "None";
        } else if (i2 == 1) {
            str = "All";
        } else if (i2 == 2) {
            str = "Weight";
        } else if (i2 == 3) {
            str = "Style";
        }
        sb.append((Object) str);
        sb.append(", resourceLoaderCacheKey=");
        sb.append(this.e);
        sb.append(')');
        return sb.toString();
    }
}
