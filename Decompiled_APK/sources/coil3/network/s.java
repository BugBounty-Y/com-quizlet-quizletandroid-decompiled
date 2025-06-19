package coil3.network;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s {
    public final String a;
    public final String b;
    public final r c;
    public final coil3.i d;

    public s(String str, String str2, r rVar, coil3.i iVar) {
        this.a = str;
        this.b = str2;
        this.c = rVar;
        this.d = iVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.a, sVar.a) && Intrinsics.b(this.b, sVar.b) && Intrinsics.b(this.c, sVar.c) && Intrinsics.b(this.d, sVar.d);
    }

    public final int hashCode() {
        return this.d.a.hashCode() + assistantMode.refactored.a.d(d0.e(this.a.hashCode() * 31, 31, this.b), 961, this.c.a);
    }

    public final String toString() {
        return "NetworkRequest(url=" + this.a + ", method=" + this.b + ", headers=" + this.c + ", body=null, extras=" + this.d + ')';
    }
}
