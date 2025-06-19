package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class k implements o {
    public final c a;
    public final String b;
    public final long c;
    public final String d;
    public final y1 e;

    public k(c data, String materialId, long j, int i) {
        j = (i & 4) != 0 ? 0L : j;
        String name = data.b;
        y1 studyMaterialType = y1.EXPLANATION_QUESTION;
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(materialId, "materialId");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = data;
        this.b = materialId;
        this.c = j;
        this.d = name;
        this.e = studyMaterialType;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final long a() {
        return this.c;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final y1 b() {
        return this.e;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final boolean c(String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        return StringsKt.G(this.a.b, query, true);
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && Intrinsics.b(this.b, kVar.b) && this.c == kVar.c && Intrinsics.b(this.d, kVar.d) && this.e == kVar.e;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String getName() {
        return this.d;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "QuestionStudyMaterial(data=" + this.a + ", materialId=" + this.b + ", timestampSec=" + this.c + ", name=" + this.d + ", studyMaterialType=" + this.e + ")";
    }
}
