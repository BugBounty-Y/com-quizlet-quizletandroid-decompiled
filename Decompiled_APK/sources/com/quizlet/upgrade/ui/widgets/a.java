package com.quizlet.upgrade.ui.widgets;

import com.quizlet.qutils.string.f;
import com.quizlet.qutils.string.g;
import com.quizlet.upgrade.data.n;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final g a;
    public final n b;
    public final f c;
    public final f d;
    public final boolean e;

    public a(g planType, n planPrice, f planFrequency, f planInfo, boolean z) {
        Intrinsics.checkNotNullParameter(planType, "planType");
        Intrinsics.checkNotNullParameter(planPrice, "planPrice");
        Intrinsics.checkNotNullParameter(planFrequency, "planFrequency");
        Intrinsics.checkNotNullParameter(planInfo, "planInfo");
        this.a = planType;
        this.b = planPrice;
        this.c = planFrequency;
        this.d = planInfo;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && this.b.equals(aVar.b) && this.c.equals(aVar.c) && this.d.equals(aVar.d) && this.e == aVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.a.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpgradePlanChoiceState(planType=");
        sb.append(this.a);
        sb.append(", planPrice=");
        sb.append(this.b);
        sb.append(", planFrequency=");
        sb.append(this.c);
        sb.append(", planInfo=");
        sb.append(this.d);
        sb.append(", isBestValue=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
