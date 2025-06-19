package coil3;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class p {
    public final Context a;
    public final coil3.request.e b;
    public final kotlin.u c;
    public final kotlin.u d;
    public final d e;

    public p(Context context, coil3.request.e eVar, kotlin.u uVar, kotlin.u uVar2, d dVar) {
        this.a = context;
        this.b = eVar;
        this.c = uVar;
        this.d = uVar2;
        this.e = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        if (!Intrinsics.b(this.a, pVar.a) || !this.b.equals(pVar.b) || !this.c.equals(pVar.c) || !this.d.equals(pVar.d)) {
            return false;
        }
        Object obj2 = g.a;
        return obj2.equals(obj2) && this.e.equals(pVar.e);
    }

    public final int hashCode() {
        return (this.e.hashCode() + ((g.a.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31;
    }

    public final String toString() {
        return "Options(application=" + this.a + ", defaults=" + this.b + ", memoryCacheLazy=" + this.c + ", diskCacheLazy=" + this.d + ", eventListenerFactory=" + g.a + ", componentRegistry=" + this.e + ", logger=null)";
    }
}
