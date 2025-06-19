package com.quizlet.features.questiontypes.data;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.measurement.internal.Z;
import com.quizlet.themes.g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final int a;
    public final Boolean b;

    public a(int i, Boolean bool) {
        this.a = i;
        this.b = bool;
    }

    public final long a(InterfaceC0806l interfaceC0806l) {
        long jF;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1830401950);
        Boolean bool = Boolean.TRUE;
        Boolean bool2 = this.b;
        if (Intrinsics.b(bool2, bool)) {
            c0814p.X(2021795061);
            jF = ((com.quizlet.themes.b) c0814p.j(g.a)).b.l();
            c0814p.p(false);
        } else if (Intrinsics.b(bool2, Boolean.FALSE)) {
            c0814p.X(2021796787);
            jF = ((com.quizlet.themes.b) c0814p.j(g.a)).b.a();
            c0814p.p(false);
        } else {
            if (bool2 != null) {
                throw Z.j(2021793442, c0814p, false);
            }
            c0814p.X(2021798427);
            jF = ((com.quizlet.themes.b) c0814p.j(g.a)).b.f();
            c0814p.p(false);
        }
        c0814p.p(false);
        return jF;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        Boolean bool = this.b;
        return iHashCode + (bool == null ? 0 : bool.hashCode());
    }

    public final String toString() {
        return "AnswerLabelState(text=" + this.a + ", isCorrect=" + this.b + ")";
    }
}
