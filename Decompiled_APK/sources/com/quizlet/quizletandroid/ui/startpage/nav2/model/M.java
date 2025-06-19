package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.quizlet.generated.enums.S0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M extends AbstractC4707c {
    public final S0 d;
    public final Integer e;
    public final boolean f;

    public M(S0 type, Integer num, int i) {
        num = (i & 2) != 0 ? null : num;
        boolean z = (i & 4) == 0;
        Intrinsics.checkNotNullParameter(type, "type");
        this.d = type;
        this.e = num;
        this.f = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        return this.d == m.d && Intrinsics.b(this.e, m.e) && this.f == m.f;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "revision_center_home_data";
    }

    public final int hashCode() {
        int iHashCode = this.d.hashCode() * 31;
        Integer num = this.e;
        return Boolean.hashCode(this.f) + ((iHashCode + (num == null ? 0 : num.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RevisionCenterData(type=");
        sb.append(this.d);
        sb.append(", daysLeft=");
        sb.append(this.e);
        sb.append(", examNameOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
