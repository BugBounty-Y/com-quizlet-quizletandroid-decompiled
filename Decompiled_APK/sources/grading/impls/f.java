package grading.impls;

import androidx.compose.animation.C0279f;
import androidx.compose.ui.text.C0981a;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.m;
import kotlin.text.n;

/* loaded from: classes3.dex */
public final class f {
    public static final grading.core.a a = new grading.core.a("AlwaysStripMarkdownClause", b.a);
    public static final grading.core.a b;
    public static final grading.core.a c;
    public static final grading.core.a d;
    public static final grading.core.a e;
    public static final grading.core.a[] f;
    public static final grading.core.a g;
    public static final grading.core.a h;
    public static final grading.core.a i;

    static {
        int i2 = 9;
        d dVar = d.k;
        e eVar = h.k;
        b = new grading.core.a(dVar, (grading.core.enums.a) null, eVar);
        c = new grading.core.a("AlwaysUnicodeNormalizeCharactersClause", new androidx.compose.foundation.lazy.grid.h(1, c.b), 4);
        d = new grading.core.a("AlwaysNormalizeSimilarCharactersClause", a.a);
        e = new grading.core.a(d.j, (grading.core.enums.a) null, c.d);
        f = new grading.core.a[]{new grading.core.a(d.d, (grading.core.enums.a) null, e.c), new grading.core.a(d.e, (grading.core.enums.a) null, e.d), new grading.core.a(d.b, (grading.core.enums.a) null, c.c), new grading.core.a(d.c, (grading.core.enums.a) null, e.b), new grading.core.a(d.f, (grading.core.enums.a) null, e.e), new grading.core.a(d.g, (grading.core.enums.a) null, e.f), new grading.core.a(d.h, (grading.core.enums.a) null, e.g), new grading.core.a(d.i, (grading.core.enums.a) null, e.h)};
        g = new grading.core.a(d.o, grading.core.enums.a.a, eVar);
        C0981a c0981a = new C0981a(new Function2[]{h.d, h.e, h.f}, i2);
        d dVar2 = d.n;
        C0279f c0279f = new C0279f(dVar2);
        androidx.compose.foundation.lazy.grid.h hVar = h.h;
        h = new grading.core.a(c0279f, (grading.core.enums.a) null, new C0981a(new Function2[]{c0981a, hVar}, i2));
        i = new grading.core.a(new C0279f(dVar2), (grading.core.enums.a) null, new C0981a(new Function2[]{c0981a, h.b, hVar}, i2));
    }

    public static final Pair a(Regex regex, String str, String str2) {
        String str3 = null;
        if (str != null && regex != null) {
            n nVar = Regex.b;
            m mVarB = regex.b(str);
            if (mVarB != null) {
                str3 = (String) CollectionsKt.firstOrNull(mVarB.b());
            }
        }
        Intrinsics.d(str3);
        return new Pair(str, regex.replace(str2, str3));
    }
}
