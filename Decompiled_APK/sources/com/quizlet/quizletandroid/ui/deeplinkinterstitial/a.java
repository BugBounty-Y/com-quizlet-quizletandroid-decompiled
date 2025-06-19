package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.infra.androidcontracts.deeplink.a a;
    public final boolean b;

    public a(com.quizlet.infra.androidcontracts.deeplink.a deepLink, boolean z) {
        Intrinsics.checkNotNullParameter(deepLink, "deepLink");
        this.a = deepLink;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "DeepLinkData(deepLink=" + this.a + ", isConfirmationRequired=" + this.b + ")";
    }
}
