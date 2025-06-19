package assistantMode.types;

import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.types.unions.ImageAttribute;
import com.google.android.gms.internal.mlkit_vision_camera.k3;
import java.util.Iterator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* renamed from: assistantMode.types.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1454a {
    public final G a;
    public final k3 b;
    public final k3 c;
    public final h d;
    public final ImageValue e;
    public final String f;
    public final String g;
    public final String h;
    public final assistantMode.utils.parsing.a i;
    public final Integer j;
    public final assistantMode.enums.m k;
    public final kotlin.u l;

    public C1454a(G term, k3 wordText, k3 definitionText, h hVar, ImageValue imageValue, String str, String str2, String str3, assistantMode.utils.parsing.a aVar, Integer num, assistantMode.enums.m mVar) {
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(wordText, "wordText");
        Intrinsics.checkNotNullParameter(definitionText, "definitionText");
        this.a = term;
        this.b = wordText;
        this.c = definitionText;
        this.d = hVar;
        this.e = imageValue;
        this.f = str;
        this.g = str2;
        this.h = str3;
        this.i = aVar;
        this.j = num;
        this.k = mVar;
        this.l = kotlin.l.b(new assistantMode.experiments.a(this, 1));
    }

    public final boolean a(assistantMode.enums.m cardSide) {
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        if (cardSide != assistantMode.enums.m.b && cardSide != assistantMode.enums.m.c) {
            return false;
        }
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        return StringsKt.g0(k3.g(i(cardSide).e())).toString().length() > 0;
    }

    public final String b(assistantMode.enums.m side) {
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        G g = this.a;
        if (iOrdinal == 0) {
            return g.f;
        }
        if (iOrdinal == 1) {
            return g.k;
        }
        if (iOrdinal == 2) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final List c(assistantMode.enums.m side) {
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        G g = this.a;
        if (iOrdinal == 0) {
            return g.m;
        }
        if (iOrdinal == 1) {
            return g.n;
        }
        if (iOrdinal == 2) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final String d(assistantMode.enums.m termSide) {
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        int iOrdinal = termSide.ordinal();
        if (iOrdinal == 0) {
            return this.f;
        }
        if (iOrdinal == 1) {
            return this.g;
        }
        if (iOrdinal == 2) {
            return this.h;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final boolean e(assistantMode.enums.m cardSide) {
        Intrinsics.checkNotNullParameter(cardSide, "cardSide");
        int iOrdinal = cardSide.ordinal();
        if (iOrdinal == 0) {
            return g(cardSide);
        }
        if (iOrdinal == 1) {
            return g(cardSide) || this.a.l != null;
        }
        if (iOrdinal == 2) {
            return this.d != null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1454a)) {
            return false;
        }
        C1454a c1454a = (C1454a) obj;
        return Intrinsics.b(this.a, c1454a.a) && Intrinsics.b(this.b, c1454a.b) && Intrinsics.b(this.c, c1454a.c) && Intrinsics.b(this.d, c1454a.d) && Intrinsics.b(this.e, c1454a.e) && Intrinsics.b(this.f, c1454a.f) && Intrinsics.b(this.g, c1454a.g) && Intrinsics.b(this.h, c1454a.h) && Intrinsics.b(this.i, c1454a.i) && Intrinsics.b(this.j, c1454a.j) && this.k == c1454a.k;
    }

    public final boolean f(List termSides) {
        Intrinsics.checkNotNullParameter(termSides, "termSides");
        if (termSides != null && termSides.isEmpty()) {
            return true;
        }
        Iterator it2 = termSides.iterator();
        while (it2.hasNext()) {
            if (!e((assistantMode.enums.m) it2.next())) {
                return false;
            }
        }
        return true;
    }

    public final boolean g(assistantMode.enums.m mVar) {
        int iOrdinal = mVar.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            return StringsKt.g0(i(mVar).e()).toString().length() > 0;
        }
        throw new IllegalStateException("Invalid textual cardSide: " + mVar);
    }

    public final ImageAttribute h(assistantMode.enums.m side) {
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        if (iOrdinal == 0) {
            return null;
        }
        if (iOrdinal == 1) {
            return this.a.l;
        }
        if (iOrdinal == 2) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31;
        h hVar = this.d;
        int iHashCode2 = (iHashCode + (hVar == null ? 0 : hVar.hashCode())) * 31;
        ImageValue imageValue = this.e;
        int iHashCode3 = (iHashCode2 + (imageValue == null ? 0 : imageValue.hashCode())) * 31;
        String str = this.f;
        int iHashCode4 = (iHashCode3 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iHashCode5 = (iHashCode4 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.h;
        int iHashCode6 = (iHashCode5 + (str3 == null ? 0 : str3.hashCode())) * 31;
        assistantMode.utils.parsing.a aVar = this.i;
        int iHashCode7 = (iHashCode6 + (aVar == null ? 0 : aVar.hashCode())) * 31;
        Integer num = this.j;
        int iHashCode8 = (iHashCode7 + (num == null ? 0 : num.hashCode())) * 31;
        assistantMode.enums.m mVar = this.k;
        return iHashCode8 + (mVar != null ? mVar.hashCode() : 0);
    }

    public final k3 i(assistantMode.enums.m termSide) {
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        int iOrdinal = termSide.ordinal();
        if (iOrdinal == 0) {
            return this.b;
        }
        if (iOrdinal == 1) {
            return this.c;
        }
        throw new IllegalStateException("Unrecognized textual card side: " + termSide);
    }

    public final String j(assistantMode.enums.m side) {
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        G g = this.a;
        if (iOrdinal == 0) {
            return g.d;
        }
        if (iOrdinal == 1) {
            return g.i;
        }
        if (iOrdinal == 2) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final String k(assistantMode.enums.m side) {
        Intrinsics.checkNotNullParameter(side, "side");
        int iOrdinal = side.ordinal();
        G g = this.a;
        if (iOrdinal == 0) {
            return g.e;
        }
        if (iOrdinal == 1) {
            return g.j;
        }
        if (iOrdinal == 2) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public final String toString() {
        return "AnnotatedCard(term=" + this.a + ", wordText=" + this.b + ", definitionText=" + this.c + ", legacyDiagramShape=" + this.d + ", diagramImage=" + this.e + ", wordEquivalenceKey=" + this.f + ", definitionEquivalenceKey=" + this.g + ", locationEquivalenceKey=" + this.h + ", parsedMcq=" + this.i + ", indexOfMcqKey=" + this.j + ", foreignLanguageSide=" + this.k + ")";
    }
}
