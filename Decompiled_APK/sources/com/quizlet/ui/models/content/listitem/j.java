package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class j implements o {
    public final g a;
    public final String b;
    public final String c;
    public final y1 d;

    public j(g data, String materialId, String name, y1 studyMaterialType) {
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(materialId, "materialId");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        this.a = data;
        this.b = materialId;
        this.c = name;
        this.d = studyMaterialType;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final long a() {
        return 0L;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final y1 b() {
        return this.d;
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
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a.equals(jVar.a) && Intrinsics.b(this.b, jVar.b) && Intrinsics.b(this.c, jVar.c) && this.d == jVar.d;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String getName() {
        return this.c;
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, 0L), 31, this.c);
    }

    public final String toString() {
        return "PracticeTestsStudyMaterial(data=" + this.a + ", materialId=" + this.b + ", timestampSec=0, name=" + this.c + ", studyMaterialType=" + this.d + ")";
    }
}
