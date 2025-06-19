package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1012m extends AbstractC1013n {
    public final String a;
    public final I b;

    public C1012m(String str, I i) {
        this.a = str;
        this.b = i;
    }

    @Override // androidx.compose.ui.text.AbstractC1013n
    public final com.quizlet.features.infra.basestudy.ui.c a() {
        return null;
    }

    @Override // androidx.compose.ui.text.AbstractC1013n
    public final I b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1012m)) {
            return false;
        }
        C1012m c1012m = (C1012m) obj;
        return this.a.equals(c1012m.a) && Intrinsics.b(this.b, c1012m.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        I i = this.b;
        return (iHashCode + (i != null ? i.hashCode() : 0)) * 31;
    }

    public final String toString() {
        return d0.r(new StringBuilder("LinkAnnotation.Url(url="), this.a, ')');
    }
}
