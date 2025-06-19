package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements b {
    public final long a;
    public final String b;
    public final int c;
    public final String d;
    public final boolean e;
    public final boolean f;

    public d(int i, long j, String title, String str, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = j;
        this.b = title;
        this.c = i;
        this.d = str;
        this.e = z;
        this.f = z2;
    }

    @Override // com.quizlet.ui.models.content.listitem.b
    public final boolean a() {
        return this.e;
    }

    @Override // com.quizlet.ui.models.content.listitem.b
    public final String b() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c && Intrinsics.b(this.d, dVar.d) && this.e == dVar.e && this.f == dVar.f;
    }

    public final int hashCode() {
        int iB = d0.b(this.c, d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31);
        String str = this.d;
        return Boolean.hashCode(this.f) + d0.g((iB + (str == null ? 0 : str.hashCode())) * 31, 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardSetContentMetadata(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", numTerms=");
        sb.append(this.c);
        sb.append(", creatorName=");
        sb.append(this.d);
        sb.append(", loggedInUserIsCreator=");
        sb.append(this.e);
        sb.append(", isDraft=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }
}
