package com.quizlet.explanations.textbook.chaptermenu.recyclerview;

import androidx.compose.animation.d0;
import com.quizlet.data.model.Section;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends a {
    public final long a;
    public final String b;
    public final String c;
    public final Section d;
    public final boolean e;
    public final com.quizlet.explanations.solution.fragments.b f;

    public i(long j, String title, String name, Section sectionData, boolean z, com.quizlet.explanations.solution.fragments.b onClickListener) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(sectionData, "sectionData");
        Intrinsics.checkNotNullParameter(onClickListener, "onClickListener");
        this.a = j;
        this.b = title;
        this.c = name;
        this.d = sectionData;
        this.e = z;
        this.f = onClickListener;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && this.b.equals(iVar.b) && this.c.equals(iVar.c) && this.d.equals(iVar.d) && this.e == iVar.e && this.f.equals(iVar.f);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.a);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.g((this.d.hashCode() + d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c)) * 31, 31, this.e);
    }

    public final String toString() {
        return "ChapterMenuSection(itemId=" + this.a + ", title=" + this.b + ", name=" + this.c + ", sectionData=" + this.d + ", hasSolutions=" + this.e + ", onClickListener=" + this.f + ")";
    }
}
