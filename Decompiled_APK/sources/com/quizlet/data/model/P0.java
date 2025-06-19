package com.quizlet.data.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class P0 {
    public final String a;
    public final String b;
    public final ArrayList c;
    public final String d;
    public final L0 e;
    public final Z0 f;
    public final C4135i0 g;
    public final LinkedHashMap h;
    public final Long i;
    public final boolean j;
    public final S k;
    public final boolean l;

    public P0(String id, String name, ArrayList questions, String createdAt, L0 l0, Z0 z0, C4135i0 c4135i0, LinkedHashMap questionCounts, Long l, boolean z, S s) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        this.a = id;
        this.b = name;
        this.c = questions;
        this.d = createdAt;
        this.e = l0;
        this.f = z0;
        this.g = c4135i0;
        this.h = questionCounts;
        this.i = l;
        this.j = z;
        this.k = s;
        this.l = s != null ? s.a : false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof P0)) {
            return false;
        }
        P0 p0 = (P0) obj;
        return Intrinsics.b(this.a, p0.a) && Intrinsics.b(this.b, p0.b) && this.c.equals(p0.c) && Intrinsics.b(this.d, p0.d) && Intrinsics.b(this.e, p0.e) && Intrinsics.b(this.f, p0.f) && Intrinsics.b(this.g, p0.g) && this.h.equals(p0.h) && Intrinsics.b(this.i, p0.i) && this.j == p0.j && Intrinsics.b(this.k, p0.k);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.h(this.c, androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b), 31), 31, this.d);
        L0 l0 = this.e;
        int iHashCode = (iE + (l0 == null ? 0 : l0.hashCode())) * 31;
        Z0 z0 = this.f;
        int iHashCode2 = (iHashCode + (z0 == null ? 0 : z0.hashCode())) * 31;
        C4135i0 c4135i0 = this.g;
        int iHashCode3 = (this.h.hashCode() + ((iHashCode2 + (c4135i0 == null ? 0 : c4135i0.hashCode())) * 31)) * 31;
        Long l = this.i;
        int iG = androidx.compose.animation.d0.g((iHashCode3 + (l == null ? 0 : l.hashCode())) * 31, 31, this.j);
        S s = this.k;
        return iG + (s != null ? s.hashCode() : 0);
    }

    public final String toString() {
        return "PracticeTestDetail(id=" + this.a + ", name=" + this.b + ", questions=" + this.c + ", createdAt=" + this.d + ", course=" + this.e + ", school=" + this.f + ", creator=" + this.g + ", questionCounts=" + this.h + ", setId=" + this.i + ", private=" + this.j + ", entitlementData=" + this.k + ")";
    }
}
