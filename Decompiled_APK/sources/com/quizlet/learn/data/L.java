package com.quizlet.learn.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class L extends N {
    public final com.quizlet.qutils.string.f a;
    public final com.quizlet.qutils.string.d b;
    public final com.quizlet.qutils.string.f c;
    public final com.quizlet.qutils.string.f d;
    public final com.quizlet.learn.viewmodel.j e;
    public final com.quizlet.learn.viewmodel.j f;

    public L(com.quizlet.qutils.string.f header, com.quizlet.qutils.string.d description, com.quizlet.qutils.string.f primaryCtaText, com.quizlet.qutils.string.f secondaryCtaText, com.quizlet.learn.viewmodel.j primaryCtaAction, com.quizlet.learn.viewmodel.j secondaryCtaAction) {
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(primaryCtaText, "primaryCtaText");
        Intrinsics.checkNotNullParameter(secondaryCtaText, "secondaryCtaText");
        Intrinsics.checkNotNullParameter(primaryCtaAction, "primaryCtaAction");
        Intrinsics.checkNotNullParameter(secondaryCtaAction, "secondaryCtaAction");
        this.a = header;
        this.b = description;
        this.c = primaryCtaText;
        this.d = secondaryCtaText;
        this.e = primaryCtaAction;
        this.f = secondaryCtaAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return this.a.equals(l.a) && this.b.equals(l.b) && this.c.equals(l.c) && this.d.equals(l.d) && this.e.equals(l.e) && this.f.equals(l.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ShowConfirmationDialog(header=" + this.a + ", description=" + this.b + ", primaryCtaText=" + this.c + ", secondaryCtaText=" + this.d + ", primaryCtaAction=" + this.e + ", secondaryCtaAction=" + this.f + ")";
    }
}
