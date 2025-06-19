package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4708d extends AbstractC4707c {
    public final kotlinx.collections.immutable.b d;

    public C4708d(kotlinx.collections.immutable.b subjectCategories) {
        Intrinsics.checkNotNullParameter(subjectCategories, "subjectCategories");
        this.d = subjectCategories;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4708d) && Intrinsics.b(this.d, ((C4708d) obj).d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "browse_by_subject_home_data";
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return "BrowseBySubjectData(subjectCategories=" + this.d + ")";
    }
}
