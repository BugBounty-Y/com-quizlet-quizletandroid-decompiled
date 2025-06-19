package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements b {
    public final String a;
    public final String b;
    public final String c;
    public final boolean d;

    public f(String uuid, String title, String str, boolean z) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(title, "title");
        this.a = uuid;
        this.b = title;
        this.c = str;
        this.d = z;
    }

    @Override // com.quizlet.ui.models.content.listitem.b
    public final boolean a() {
        return this.d;
    }

    @Override // com.quizlet.ui.models.content.listitem.b
    public final String b() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && this.d == fVar.d;
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return Boolean.hashCode(this.d) + ((iE + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NotesContentMetadata(uuid=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", creatorName=");
        sb.append(this.c);
        sb.append(", loggedInUserIsCreator=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
