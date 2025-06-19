package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class l implements o {
    public final d a;
    public final String b;
    public final long c;
    public final String d;
    public final y1 e;

    public l(d data, String materialId, long j, String name, y1 studyMaterialType) {
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
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        return Intrinsics.b(this.a, lVar.a) && Intrinsics.b(this.b, lVar.b) && this.c == lVar.c && Intrinsics.b(this.d, lVar.d) && this.e == lVar.e;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String getName() {
        return this.d;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "SetStudyMaterial(data=" + this.a + ", materialId=" + this.b + ", timestampSec=" + this.c + ", name=" + this.d + ", studyMaterialType=" + this.e + ")";
    }

    public l(d dVar, String str, long j, int i) {
        this(dVar, str, (i & 4) != 0 ? 0L : j, dVar.b, y1.SET);
    }
}
