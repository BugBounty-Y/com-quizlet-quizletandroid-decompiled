package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x extends C {
    public final ArrayList d;
    public final AbstractC3603d6 e;

    public x(ArrayList data, AbstractC3603d6 abstractC3603d6) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
        this.e = abstractC3603d6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return this.d.equals(xVar.d) && Intrinsics.b(this.e, xVar.e);
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.model.C
    public final List g() {
        return this.d;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "horizontal_behavior_recs_data";
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.model.C
    public final AbstractC3603d6 h() {
        return this.e;
    }

    public final int hashCode() {
        int iHashCode = this.d.hashCode() * 31;
        AbstractC3603d6 abstractC3603d6 = this.e;
        return iHashCode + (abstractC3603d6 == null ? 0 : abstractC3603d6.hashCode());
    }

    public final String toString() {
        return "HorizontalBehaviorRecommendationStudySetHomeData(data=" + this.d + ", recommendationSource=" + this.e + ")";
    }
}
