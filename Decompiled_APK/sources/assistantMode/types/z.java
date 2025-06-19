package assistantMode.types;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.StudiableContainerType$Companion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z {
    public final long a;
    public final Long b;
    public final Long c;
    public final Long d;
    public final Long e;
    public final String f;
    public final String g;
    public final String h;
    public final Boolean i;
    public final Boolean j;
    public final Long k;
    public final String l;
    public final String m;
    public final int n;
    public final boolean o;
    public final Long p;
    public final Long q;
    public final Long r;
    public final boolean s;
    public final String t;
    public final String u;

    public z(long j, Long l, Long l2, Long l3, Long l4, String wordLang, String defLang, String str, Boolean bool, Boolean bool2, Long l5, String str2, String str3, int i, boolean z, Long l6, Long l7, Long l8, boolean z2, String str4, String str5) {
        Intrinsics.checkNotNullParameter(wordLang, "wordLang");
        Intrinsics.checkNotNullParameter(defLang, "defLang");
        this.a = j;
        this.b = l;
        this.c = l2;
        this.d = l3;
        this.e = l4;
        this.f = wordLang;
        this.g = defLang;
        this.h = str;
        this.i = bool;
        this.j = bool2;
        this.k = l5;
        this.l = str2;
        this.m = str3;
        this.n = i;
        this.o = z;
        this.p = l6;
        this.q = l7;
        this.r = l8;
        this.s = z2;
        this.t = str4;
        this.u = str5;
        StudiableContainerType$Companion studiableContainerType$Companion = assistantMode.refactored.enums.j.Companion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return this.a == zVar.a && this.b.equals(zVar.b) && this.c.equals(zVar.c) && this.d.equals(zVar.d) && this.e.equals(zVar.e) && Intrinsics.b(this.f, zVar.f) && Intrinsics.b(this.g, zVar.g) && Intrinsics.b(this.h, zVar.h) && this.i.equals(zVar.i) && this.j.equals(zVar.j) && this.k.equals(zVar.k) && Intrinsics.b(this.l, zVar.l) && Intrinsics.b(this.m, zVar.m) && this.n == zVar.n && this.o == zVar.o && this.p.equals(zVar.p) && this.q.equals(zVar.q) && this.r.equals(zVar.r) && this.s == zVar.s && Intrinsics.b(this.t, zVar.t) && Intrinsics.b(this.u, zVar.u);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31)) * 31)) * 31)) * 31, 31, this.f), 31, this.g);
        String str = this.h;
        int iHashCode = (this.k.hashCode() + ((this.j.hashCode() + ((this.i.hashCode() + ((iE + (str == null ? 0 : str.hashCode())) * 31)) * 31)) * 31)) * 31;
        String str2 = this.l;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.m;
        int iG = d0.g((this.r.hashCode() + ((this.q.hashCode() + ((this.p.hashCode() + d0.g(d0.b(this.n, (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31, 31), 31, this.o)) * 31)) * 31)) * 31, 31, this.s);
        String str4 = this.t;
        int iHashCode3 = (iG + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.u;
        return (iHashCode3 + (str5 != null ? str5.hashCode() : 0)) * 31;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Set(id=");
        sb.append(this.a);
        sb.append(", timestamp=");
        sb.append(this.b);
        sb.append(", lastModified=");
        sb.append(this.c);
        sb.append(", publishedTimestamp=");
        sb.append(this.d);
        sb.append(", creatorId=");
        sb.append(this.e);
        sb.append(", wordLang=");
        sb.append(this.f);
        sb.append(", defLang=");
        sb.append(this.g);
        sb.append(", title=");
        sb.append(this.h);
        sb.append(", passwordUse=");
        sb.append(this.i);
        sb.append(", passwordEdit=");
        sb.append(this.j);
        sb.append(", accessType=");
        sb.append(this.k);
        sb.append(", accessCodePrefix=");
        sb.append(this.l);
        sb.append(", description=");
        sb.append(this.m);
        sb.append(", numTerms=");
        sb.append(this.n);
        sb.append(", hasImages=");
        sb.append(this.o);
        sb.append(", parentId=");
        sb.append(this.p);
        sb.append(", creationSource=");
        sb.append(this.q);
        sb.append(", privacyLockStatus=");
        sb.append(this.r);
        sb.append(", hasDiagrams=");
        sb.append(this.s);
        sb.append(", _webUrl=");
        sb.append(this.t);
        sb.append(", _thumbnailUrl=");
        return android.support.v4.media.session.a.t(sb, this.u, ", price=null)");
    }
}
