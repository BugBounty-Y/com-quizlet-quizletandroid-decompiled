package com.quizlet.features.settings.composables;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final Function0 a;
    public final Function0 b;
    public final Function0 c;
    public final Function0 d;

    public a(Function0 onPrivacyPolicyClick, Function0 onTermsOfServiceClick, Function0 onOpenSourceClick, Function0 onHelpCenterClick) {
        Intrinsics.checkNotNullParameter(onPrivacyPolicyClick, "onPrivacyPolicyClick");
        Intrinsics.checkNotNullParameter(onTermsOfServiceClick, "onTermsOfServiceClick");
        Intrinsics.checkNotNullParameter(onOpenSourceClick, "onOpenSourceClick");
        Intrinsics.checkNotNullParameter(onHelpCenterClick, "onHelpCenterClick");
        this.a = onPrivacyPolicyClick;
        this.b = onTermsOfServiceClick;
        this.c = onOpenSourceClick;
        this.d = onHelpCenterClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "AboutActions(onPrivacyPolicyClick=" + this.a + ", onTermsOfServiceClick=" + this.b + ", onOpenSourceClick=" + this.c + ", onHelpCenterClick=" + this.d + ")";
    }
}
