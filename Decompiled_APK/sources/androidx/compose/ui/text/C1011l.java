package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1011l extends AbstractC1013n {
    public final String a;
    public final I b;
    public final com.quizlet.features.infra.basestudy.ui.c c;

    public C1011l(String str, I i, com.quizlet.features.infra.basestudy.ui.c cVar) {
        this.a = str;
        this.b = i;
        this.c = cVar;
    }

    @Override // androidx.compose.ui.text.AbstractC1013n
    public final com.quizlet.features.infra.basestudy.ui.c a() {
        return this.c;
    }

    @Override // androidx.compose.ui.text.AbstractC1013n
    public final I b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1011l)) {
            return false;
        }
        C1011l c1011l = (C1011l) obj;
        if (!Intrinsics.b(this.a, c1011l.a)) {
            return false;
        }
        if (Intrinsics.b(this.b, c1011l.b)) {
            return Intrinsics.b(this.c, c1011l.c);
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        I i = this.b;
        int iHashCode2 = (iHashCode + (i != null ? i.hashCode() : 0)) * 31;
        com.quizlet.features.infra.basestudy.ui.c cVar = this.c;
        return iHashCode2 + (cVar != null ? cVar.hashCode() : 0);
    }

    public final String toString() {
        return d0.r(new StringBuilder("LinkAnnotation.Clickable(tag="), this.a, ')');
    }
}
