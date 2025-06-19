package com.quizlet.quizletandroid.ui.group.classcontent.models;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends a {
    public final com.quizlet.features.infra.legacyadapter.section.b a;

    public e(com.quizlet.features.infra.legacyadapter.section.b headerSection) {
        Intrinsics.checkNotNullParameter("", "name");
        Intrinsics.checkNotNullParameter(headerSection, "headerSection");
        this.a = headerSection;
    }

    @Override // com.quizlet.quizletandroid.ui.group.classcontent.models.a
    public final long a() {
        return 0L;
    }

    @Override // com.quizlet.quizletandroid.ui.group.classcontent.models.a
    public final long b() {
        return 0L;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        eVar.getClass();
        return this.a.equals(eVar.a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TimestampHeaderClassContentItem(name=, headerSection=" + this.a + ")";
    }
}
