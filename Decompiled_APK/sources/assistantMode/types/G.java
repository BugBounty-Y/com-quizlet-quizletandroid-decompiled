package assistantMode.types;

import androidx.compose.animation.d0;
import assistantMode.types.unions.ImageAttribute;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G {
    public final long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;
    public final String j;
    public final String k;
    public final ImageAttribute l;
    public final ArrayList m;
    public final ArrayList n;
    public final long o;
    public final Long p;

    public G(long j, String word, String str, String str2, String str3, String str4, String definition, String str5, String str6, String str7, String str8, ImageAttribute imageAttribute, ArrayList arrayList, ArrayList arrayList2, long j2, Long l) {
        Intrinsics.checkNotNullParameter(word, "word");
        Intrinsics.checkNotNullParameter(definition, "definition");
        this.a = j;
        this.b = word;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = str4;
        this.g = definition;
        this.h = str5;
        this.i = str6;
        this.j = str7;
        this.k = str8;
        this.l = imageAttribute;
        this.m = arrayList;
        this.n = arrayList2;
        this.o = j2;
        this.p = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return this.a == g.a && Intrinsics.b(this.b, g.b) && Intrinsics.b(this.c, g.c) && Intrinsics.b(this.d, g.d) && Intrinsics.b(this.e, g.e) && Intrinsics.b(this.f, g.f) && Intrinsics.b(this.g, g.g) && Intrinsics.b(this.h, g.h) && Intrinsics.b(this.i, g.i) && Intrinsics.b(this.j, g.j) && Intrinsics.b(this.k, g.k) && Intrinsics.b(this.l, g.l) && Intrinsics.b(this.m, g.m) && Intrinsics.b(this.n, g.n) && this.o == g.o && this.p.equals(g.p);
    }

    public final int hashCode() {
        int iE = d0.e(Long.hashCode(this.a) * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        int iHashCode3 = (iHashCode2 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.f;
        int iE2 = d0.e((iHashCode3 + (str4 == null ? 0 : str4.hashCode())) * 31, 31, this.g);
        String str5 = this.h;
        int iHashCode4 = (iE2 + (str5 == null ? 0 : str5.hashCode())) * 31;
        String str6 = this.i;
        int iHashCode5 = (iHashCode4 + (str6 == null ? 0 : str6.hashCode())) * 31;
        String str7 = this.j;
        int iHashCode6 = (iHashCode5 + (str7 == null ? 0 : str7.hashCode())) * 31;
        String str8 = this.k;
        int iHashCode7 = (iHashCode6 + (str8 == null ? 0 : str8.hashCode())) * 31;
        ImageAttribute imageAttribute = this.l;
        int iHashCode8 = (iHashCode7 + (imageAttribute == null ? 0 : imageAttribute.hashCode())) * 31;
        ArrayList arrayList = this.m;
        int iHashCode9 = (iHashCode8 + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        ArrayList arrayList2 = this.n;
        return this.p.hashCode() + d0.d((iHashCode9 + (arrayList2 != null ? arrayList2.hashCode() : 0)) * 31, 961, this.o);
    }

    public final String toString() {
        return "Term(id=" + this.a + ", word=" + this.b + ", wordRichText=" + this.c + ", _wordTtsUrl=" + this.d + ", _wordSlowTtsUrl=" + this.e + ", _wordAudioUrl=" + this.f + ", definition=" + this.g + ", definitionRichText=" + this.h + ", _definitionTtsUrl=" + this.i + ", _definitionSlowTtsUrl=" + this.j + ", _definitionAudioUrl=" + this.k + ", definitionImage=" + this.l + ", wordDistractors=" + this.m + ", definitionDistractors=" + this.n + ", setId=" + this.o + ", rank=null, lastModified=" + this.p + ")";
    }
}
