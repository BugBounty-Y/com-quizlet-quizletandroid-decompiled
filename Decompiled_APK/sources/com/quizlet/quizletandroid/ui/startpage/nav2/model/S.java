package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class S extends AbstractC4707c implements InterfaceC4751w {
    public final DBStudySet d;
    public final Long e;
    public final int f;
    public final w1 g;
    public final EnumC4525u1 h;
    public final boolean i;

    public S(DBStudySet data, Long l, w1 subplacement, boolean z) {
        EnumC4525u1 placement = EnumC4525u1.HOMESCREEN;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(placement, "placement");
        this.d = data;
        this.e = l;
        this.f = 1;
        this.g = subplacement;
        this.h = placement;
        this.i = z;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final w1 a() {
        return this.g;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final Long b() {
        return this.e;
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final EnumC4525u1 c() {
        return this.h;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S)) {
            return false;
        }
        S s = (S) obj;
        return Intrinsics.b(this.d, s.d) && Intrinsics.b(this.e, s.e) && this.f == s.f && this.g == s.g && this.h == s.h && this.i == s.i;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return d0.n(this.d.getId(), "study_set_home_data_");
    }

    @Override // com.quizlet.quizletandroid.ui.startpage.nav2.InterfaceC4751w
    public final int getModelType() {
        return this.f;
    }

    public final int hashCode() {
        int iHashCode = this.d.hashCode() * 31;
        Long l = this.e;
        return Boolean.hashCode(this.i) + ((this.h.hashCode() + ((this.g.hashCode() + d0.b(this.f, (iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySetHomeData(data=");
        sb.append(this.d);
        sb.append(", modelId=");
        sb.append(this.e);
        sb.append(", modelType=");
        sb.append(this.f);
        sb.append(", subplacement=");
        sb.append(this.g);
        sb.append(", placement=");
        sb.append(this.h);
        sb.append(", isRecommended=");
        return android.support.v4.media.session.a.o(")", sb, this.i);
    }
}
