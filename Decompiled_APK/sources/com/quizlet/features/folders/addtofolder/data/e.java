package com.quizlet.features.folders.addtofolder.data;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements n {
    public final List a;
    public final long b;
    public final long c;
    public final String d;
    public final boolean e;

    public e(List studyMaterials, long j, long j2, String selectedTag, boolean z) {
        Intrinsics.checkNotNullParameter(studyMaterials, "studyMaterials");
        Intrinsics.checkNotNullParameter(selectedTag, "selectedTag");
        this.a = studyMaterials;
        this.b = j;
        this.c = j2;
        this.d = selectedTag;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b && this.c == eVar.c && Intrinsics.b(this.d, eVar.d) && this.e == eVar.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.e(d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("InitializeSelected(studyMaterials=");
        sb.append(this.a);
        sb.append(", creatorId=");
        sb.append(this.b);
        sb.append(", folderId=");
        sb.append(this.c);
        sb.append(", selectedTag=");
        sb.append(this.d);
        sb.append(", isVisible=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
