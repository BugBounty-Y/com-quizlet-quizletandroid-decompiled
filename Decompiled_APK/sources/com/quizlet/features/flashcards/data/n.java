package com.quizlet.features.flashcards.data;

import com.quizlet.assembly.compose.buttons.C4090o;
import com.quizlet.assembly.compose.buttons.InterfaceC4092q;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n {
    public final int a;
    public final C4956o b;
    public final InterfaceC4092q c;
    public final Function2 d;

    /* JADX WARN: Multi-variable type inference failed */
    public n(int i, Function0 onClick, InterfaceC4092q loadingState, Function2 function2) {
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        Intrinsics.checkNotNullParameter(loadingState, "loadingState");
        this.a = i;
        this.b = (C4956o) onClick;
        this.c = loadingState;
        this.d = function2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return this.a == nVar.a && Intrinsics.b(this.b, nVar.b) && Intrinsics.b(this.c, nVar.c) && Intrinsics.b(this.d, nVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + ((this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31)) * 31;
        Function2 function2 = this.d;
        return iHashCode + (function2 == null ? 0 : function2.hashCode());
    }

    public final String toString() {
        return "FlashcardsSummaryCtaData(ctaStringRes=" + this.a + ", onClick=" + this.b + ", loadingState=" + this.c + ", startIconRes=" + this.d + ")";
    }

    public /* synthetic */ n(int i, int i2, Function0 function0) {
        this(i, function0, C4090o.a, (i2 & 8) != 0 ? null : c.c);
    }
}
