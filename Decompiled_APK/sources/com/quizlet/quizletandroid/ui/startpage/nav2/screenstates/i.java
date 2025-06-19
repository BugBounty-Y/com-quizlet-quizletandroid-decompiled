package com.quizlet.quizletandroid.ui.startpage.nav2.screenstates;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3619f6;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends AbstractC3619f6 {
    public final List a;

    public i(List data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("HomeAchievementsSectionState(data="), this.a);
    }
}
