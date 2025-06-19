package com.quizlet.scandocument.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final String a;
    public final Object b;

    public d(String locale, List annotations) {
        Intrinsics.checkNotNullParameter(locale, "locale");
        Intrinsics.checkNotNullParameter(annotations, "annotations");
        this.a = locale;
        this.b = annotations;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a.equals(dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OcrAnnotationData(locale=");
        sb.append(this.a);
        sb.append(", annotations=");
        return android.support.v4.media.session.a.s(sb, this.b, ")");
    }
}
