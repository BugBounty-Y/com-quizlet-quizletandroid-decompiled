package com.quizlet.upgrade.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I {
    public final com.quizlet.billing.subscriptions.j a;
    public final String b;

    public I(com.quizlet.billing.subscriptions.j targetPackage, String str) {
        Intrinsics.checkNotNullParameter(targetPackage, "targetPackage");
        this.a = targetPackage;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return this.a == i.a && Intrinsics.b(this.b, i.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 961;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpgradePurchaseData(targetPackage=");
        sb.append(this.a);
        sb.append(", oldPackage=null, source=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
