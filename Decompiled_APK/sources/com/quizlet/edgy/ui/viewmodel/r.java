package com.quizlet.edgy.ui.viewmodel;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class r {
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final EnumC4212m f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final boolean j;
    public final boolean k;
    public final boolean l;

    public r(boolean z, boolean z2, boolean z3, boolean z4, boolean z5, EnumC4212m recyclerViewAdapter, boolean z6, boolean z7, boolean z8, boolean z9, boolean z10, boolean z11) {
        Intrinsics.checkNotNullParameter(recyclerViewAdapter, "recyclerViewAdapter");
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
        this.e = z5;
        this.f = recyclerViewAdapter;
        this.g = z6;
        this.h = z7;
        this.i = z8;
        this.j = z9;
        this.k = z10;
        this.l = z11;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && this.b == rVar.b && this.c == rVar.c && this.d == rVar.d && this.e == rVar.e && this.f == rVar.f && this.g == rVar.g && this.h == rVar.h && this.i == rVar.i && this.j == rVar.j && this.k == rVar.k && this.l == rVar.l;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.l) + d0.g(d0.g(d0.g(d0.g(d0.g((this.f.hashCode() + d0.g(d0.g(d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e)) * 31, 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ViewsVisibility(searchSchoolInputLayoutVisible=");
        sb.append(this.a);
        sb.append(", emptyResultsTextVisible=");
        sb.append(this.b);
        sb.append(", searchSchoolEditTextEnabled=");
        sb.append(this.c);
        sb.append(", searchCoursesInputLayoutVisible=");
        sb.append(this.d);
        sb.append(", loadingVisible=");
        sb.append(this.e);
        sb.append(", recyclerViewAdapter=");
        sb.append(this.f);
        sb.append(", clearSearchSchoolEditText=");
        sb.append(this.g);
        sb.append(", clearSearchCourseEditText=");
        sb.append(this.h);
        sb.append(", searchSchoolEditTextRequestFocus=");
        sb.append(this.i);
        sb.append(", searchCourseEditTextRequestFocus=");
        sb.append(this.j);
        sb.append(", showDivider=");
        sb.append(this.k);
        sb.append(", showBtnDone=");
        return android.support.v4.media.session.a.o(")", sb, this.l);
    }
}
