package com.quizlet.ui.models.content.listitem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class m implements o {
    public final q a;
    public final String b;
    public final long c;
    public final String d;
    public final y1 e;

    /* JADX WARN: Illegal instructions before constructor call */
    public m(q qVar, String str, long j, int i) {
        long j2 = (i & 4) != 0 ? 0L : j;
        String str2 = qVar.i.b;
        String str3 = qVar.e;
        String strConcat = (str3 == null || (strConcat = " ".concat(str3)) == null) ? "" : strConcat;
        StringBuilder sbX = android.support.v4.media.session.a.x(str2, " ");
        sbX.append(qVar.c);
        sbX.append(strConcat);
        sbX.append(" ");
        sbX.append(qVar.b);
        this(qVar, str, j2, sbX.toString(), y1.TEXTBOOK_EXERCISE);
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
        String str;
        String str2;
        String str3;
        Intrinsics.checkNotNullParameter(query, "query");
        q qVar = this.a;
        return StringsKt.G(qVar.b, query, true) || ((str = qVar.d) != null && StringsKt.G(str, query, true)) || (((str2 = qVar.f) != null && StringsKt.G(str2, query, true)) || (((str3 = qVar.g) != null && StringsKt.G(str3, query, true)) || StringsKt.G(qVar.i.b, query, true)));
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && Intrinsics.b(this.b, mVar.b) && this.c == mVar.c && Intrinsics.b(this.d, mVar.d) && this.e == mVar.e;
    }

    @Override // com.quizlet.ui.models.content.listitem.o
    public final String getName() {
        return this.d;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "TextbookExerciseStudyMaterial(data=" + this.a + ", materialId=" + this.b + ", timestampSec=" + this.c + ", name=" + this.d + ", studyMaterialType=" + this.e + ")";
    }

    public m(q data, String materialId, long j, String name, y1 studyMaterialType) {
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
}
