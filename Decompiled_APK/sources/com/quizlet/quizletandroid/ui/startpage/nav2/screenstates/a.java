package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final int a;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.model.u b;
    public final int c;

    public a(int i, com.quizlet.quizletandroid.ui.startpage.nav2.model.u homeSectionType, int i2) {
        Intrinsics.checkNotNullParameter(homeSectionType, "homeSectionType");
        this.a = i;
        this.b = homeSectionType;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + ((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CheckImpressionsOnChildren(index=");
        sb.append(this.a);
        sb.append(", homeSectionType=");
        sb.append(this.b);
        sb.append(", recsSectionNumber=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
