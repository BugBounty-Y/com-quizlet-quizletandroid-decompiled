package com.quizlet.features.practicetest.results.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e {
    public final String a;
    public final String b;

    public e(String option, String str) {
        Intrinsics.checkNotNullParameter(option, "option");
        this.a = option;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MultipleChoiceOption(option=");
        sb.append(this.a);
        sb.append(", imageUrl=");
        return android.support.v4.media.session.a.t(sb, this.b, ", imageCaption=null)");
    }
}
