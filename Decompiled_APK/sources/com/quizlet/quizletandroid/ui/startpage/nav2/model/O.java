package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O extends AbstractC4707c {
    public final P d;
    public final AbstractC3603d6 e;

    public O(P type, AbstractC3603d6 abstractC3603d6) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.d = type;
        this.e = abstractC3603d6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        O o = (O) obj;
        return this.d == o.d && Intrinsics.b(this.e, o.e);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return "section_header_id_" + this.d;
    }

    public final int hashCode() {
        int iHashCode = this.d.hashCode() * 31;
        AbstractC3603d6 abstractC3603d6 = this.e;
        return iHashCode + (abstractC3603d6 == null ? 0 : abstractC3603d6.hashCode());
    }

    public final String toString() {
        return "SectionHeaderHomeData(type=" + this.d + ", recommendationSource=" + this.e + ")";
    }
}
