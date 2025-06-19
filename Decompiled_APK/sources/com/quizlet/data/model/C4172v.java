package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4172v {
    public final Object a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final List g;

    public C4172v(List sets, List textbooks, List questions, List users, List qClasses, List terms, List shelfRanking) {
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(textbooks, "textbooks");
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(users, "users");
        Intrinsics.checkNotNullParameter(qClasses, "qClasses");
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(shelfRanking, "shelfRanking");
        this.a = sets;
        this.b = textbooks;
        this.c = questions;
        this.d = users;
        this.e = qClasses;
        this.f = terms;
        this.g = shelfRanking;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4172v)) {
            return false;
        }
        C4172v c4172v = (C4172v) obj;
        return Intrinsics.b(this.a, c4172v.a) && Intrinsics.b(this.b, c4172v.b) && Intrinsics.b(this.c, c4172v.c) && Intrinsics.b(this.d, c4172v.d) && Intrinsics.b(this.e, c4172v.e) && Intrinsics.b(this.f, c4172v.f) && Intrinsics.b(this.g, c4172v.g);
    }

    public final int hashCode() {
        return this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AllResultsSearchResult(sets=");
        sb.append(this.a);
        sb.append(", textbooks=");
        sb.append(this.b);
        sb.append(", questions=");
        sb.append(this.c);
        sb.append(", users=");
        sb.append(this.d);
        sb.append(", qClasses=");
        sb.append(this.e);
        sb.append(", terms=");
        sb.append(this.f);
        sb.append(", shelfRanking=");
        return android.support.v4.media.session.a.n(")", sb, this.g);
    }
}
