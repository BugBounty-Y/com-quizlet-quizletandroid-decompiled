package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J extends AbstractC4707c {
    public final K d;

    public J(K data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof J) && Intrinsics.b(this.d, ((J) obj).d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "rate_us_id";
    }

    public final int hashCode() {
        return this.d.a.hashCode();
    }

    public final String toString() {
        return "RateUsHomeData(data=" + this.d + ")";
    }
}
