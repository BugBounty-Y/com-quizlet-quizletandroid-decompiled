package com.quizlet.features.infra.basestudy.usecase;

import com.quizlet.data.model.InterfaceC4176w0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final InterfaceC4176w0 a;
    public final boolean b;

    public e(InterfaceC4176w0 meteredEvent, boolean z) {
        Intrinsics.checkNotNullParameter(meteredEvent, "meteredEvent");
        this.a = meteredEvent;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnNavigation(meteredEvent=");
        sb.append(this.a);
        sb.append(", shouldShowOnboarding=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
