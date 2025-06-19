package com.quizlet.ui.models.content.home;

import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.quizlet.generated.enums.S0;
import com.quizlet.qutils.string.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends f {
    public final S0 c;
    public final Integer d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(S0 revisionCenterType, Integer num) {
        super(Y5.c(revisionCenterType), 0);
        Intrinsics.checkNotNullParameter(revisionCenterType, "revisionCenterType");
        this.c = revisionCenterType;
        this.d = num;
    }

    @Override // com.quizlet.ui.models.content.home.f
    public final g a() {
        return Y5.d(this.c);
    }

    @Override // com.quizlet.ui.models.content.home.f
    public final g b() {
        return Y5.a(this.c, this.d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.c == dVar.c && Intrinsics.b(this.d, dVar.d);
    }

    public final int hashCode() {
        int iHashCode = this.c.hashCode() * 31;
        Integer num = this.d;
        return iHashCode + (num == null ? 0 : num.hashCode());
    }

    public final String toString() {
        return "RevisionCenter(revisionCenterType=" + this.c + ", daysLeft=" + this.d + ")";
    }
}
