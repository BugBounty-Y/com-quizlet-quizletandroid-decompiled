package grading.rules;

import androidx.compose.animation.C0279f;
import androidx.compose.foundation.lazy.grid.h;
import grading.core.c;
import grading.impls.d;
import grading.impls.f;
import grading.impls.levenshteinplus.e;
import kotlin.collections.C4930v;

/* loaded from: classes3.dex */
public abstract class a {
    public static final c[] a;

    static {
        d dVar = d.l;
        C0279f c0279f = new C0279f(dVar);
        h hVar = grading.impls.h.c;
        grading.core.a[] aVarArr = {new grading.core.a(c0279f, (grading.core.enums.a) null, hVar), new grading.core.a(d.m, (grading.core.enums.a) null, grading.impls.h.a), new grading.core.a(d.p, (grading.core.enums.a) null, grading.impls.h.i), f.b, f.e, new grading.core.a(new C0279f(dVar), (grading.core.enums.a) null, hVar), f.g, new grading.core.a("Always remove punctuation", grading.impls.h.g, 6), new grading.core.a("Trim leading and trailing whitespace regardless of language", grading.impls.h.j, 6), new grading.core.a("postProcess", grading.impls.h.l, 6), e.a, grading.impls.levenshteinplus.c.a};
        a = new c[]{new c("Include content in parentheses", "en", "en", (grading.core.a[]) C4930v.s(new grading.core.a[]{f.h}, aVarArr)), new c("Ignore content in parentheses", "en", "en", (grading.core.a[]) C4930v.s(new grading.core.a[]{f.i}, aVarArr))};
    }
}
