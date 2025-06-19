package com.quizlet.learn.ui;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final com.quizlet.ui.states.a a;
    public final com.quizlet.qutils.string.d b;
    public final com.quizlet.qutils.string.f c;

    public g(com.quizlet.ui.states.a plusLogoVariant, com.quizlet.qutils.string.d prompt, com.quizlet.qutils.string.f description) {
        Intrinsics.checkNotNullParameter(plusLogoVariant, "plusLogoVariant");
        Intrinsics.checkNotNullParameter(prompt, "prompt");
        Intrinsics.checkNotNullParameter(description, "description");
        this.a = plusLogoVariant;
        this.b = prompt;
        this.c = description;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && this.b.equals(gVar.b) && this.c.equals(gVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "ViewState(plusLogoVariant=" + this.a + ", prompt=" + this.b + ", description=" + this.c + ")";
    }
}
