package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3619f6;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends AbstractC3619f6 {
    public final List a;

    public k(List rateUsData) {
        Intrinsics.checkNotNullParameter(rateUsData, "rateUsData");
        this.a = rateUsData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.a, ((k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("HomeRateUsState(rateUsData="), this.a);
    }
}
