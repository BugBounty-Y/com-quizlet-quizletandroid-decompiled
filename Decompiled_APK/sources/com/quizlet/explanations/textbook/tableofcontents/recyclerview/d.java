package com.quizlet.explanations.textbook.tableofcontents.recyclerview;

import androidx.compose.animation.d0;
import com.quizlet.data.model.Chapter;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends a {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final Chapter e;
    public final com.quizlet.explanations.solution.fragments.b f;

    public d(long j, String name, String title, boolean z, Chapter chapter, com.quizlet.explanations.solution.fragments.b bVar) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(chapter, "chapter");
        this.a = j;
        this.b = name;
        this.c = title;
        this.d = z;
        this.e = chapter;
        this.f = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b.equals(dVar.b) && this.c.equals(dVar.c) && this.d == dVar.d && this.e.equals(dVar.e) && this.f.equals(dVar.f);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.a);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + d0.g(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d)) * 31);
    }

    public final String toString() {
        return "ChapterItem(itemId=" + this.a + ", name=" + this.b + ", title=" + this.c + ", hasSolutions=" + this.d + ", chapter=" + this.e + ", onClickListener=" + this.f + ")";
    }
}
