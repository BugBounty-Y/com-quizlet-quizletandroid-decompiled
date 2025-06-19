package coil3.request;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public final Context a;
    public final coil3.size.h b;
    public final coil3.size.g c;
    public final coil3.size.d d;
    public final String e;
    public final okio.n f;
    public final b g;
    public final b h;
    public final b i;
    public final coil3.i j;

    public m(Context context, coil3.size.h hVar, coil3.size.g gVar, coil3.size.d dVar, String str, okio.n nVar, b bVar, b bVar2, b bVar3, coil3.i iVar) {
        this.a = context;
        this.b = hVar;
        this.c = gVar;
        this.d = dVar;
        this.e = str;
        this.f = nVar;
        this.g = bVar;
        this.h = bVar2;
        this.i = bVar3;
        this.j = iVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b) && this.c == mVar.c && this.d == mVar.d && Intrinsics.b(this.e, mVar.e) && Intrinsics.b(this.f, mVar.f) && this.g == mVar.g && this.h == mVar.h && this.i == mVar.i && Intrinsics.b(this.j, mVar.j);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31;
        String str = this.e;
        return this.j.a.hashCode() + ((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Options(context=" + this.a + ", size=" + this.b + ", scale=" + this.c + ", precision=" + this.d + ", diskCacheKey=" + this.e + ", fileSystem=" + this.f + ", memoryCachePolicy=" + this.g + ", diskCachePolicy=" + this.h + ", networkCachePolicy=" + this.i + ", extras=" + this.j + ')';
    }
}
