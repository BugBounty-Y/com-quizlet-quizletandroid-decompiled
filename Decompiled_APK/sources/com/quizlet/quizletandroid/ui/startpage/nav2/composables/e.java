package com.quizlet.quizletandroid.ui.startpage.nav2.composables;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final com.quizlet.ui.models.content.home.f a;
    public final Function0 b;

    public e(com.quizlet.ui.models.content.home.f cardType, Function0 onClick) {
        Intrinsics.checkNotNullParameter(cardType, "cardType");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = cardType;
        this.b = onClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GetStartedCardData(cardType=" + this.a + ", onClick=" + this.b + ")";
    }
}
