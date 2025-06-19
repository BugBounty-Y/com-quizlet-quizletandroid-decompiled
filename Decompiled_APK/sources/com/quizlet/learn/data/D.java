package com.quizlet.learn.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends N {
    public final String a;
    public final com.quizlet.features.infra.studysetting.managers.a b;
    public final boolean c;

    public D(String setTitle, com.quizlet.features.infra.studysetting.managers.a studySettingsManager, boolean z) {
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        Intrinsics.checkNotNullParameter(studySettingsManager, "studySettingsManager");
        this.a = setTitle;
        this.b = studySettingsManager;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return Intrinsics.b(this.a, d.a) && Intrinsics.b(this.b, d.b) && this.c == d.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToLearnOnboarding(setTitle=");
        sb.append(this.a);
        sb.append(", studySettingsManager=");
        sb.append(this.b);
        sb.append(", hasDiagrams=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
