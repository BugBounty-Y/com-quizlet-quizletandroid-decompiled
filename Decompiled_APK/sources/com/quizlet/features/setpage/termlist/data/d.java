package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_common.C;

/* loaded from: classes3.dex */
public final class d extends C {
    public final boolean a;

    public d(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && this.a == ((d) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("ControlStateClick(isSelected="), this.a);
    }
}
