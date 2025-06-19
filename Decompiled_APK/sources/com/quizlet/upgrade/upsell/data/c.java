package com.quizlet.upgrade.upsell.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final b a;
    public final b b;
    public final b c;

    public c(b firstValueProp, b secondValueProp, b thirdValueProp) {
        Intrinsics.checkNotNullParameter(firstValueProp, "firstValueProp");
        Intrinsics.checkNotNullParameter(secondValueProp, "secondValueProp");
        Intrinsics.checkNotNullParameter(thirdValueProp, "thirdValueProp");
        this.a = firstValueProp;
        this.b = secondValueProp;
        this.c = thirdValueProp;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "UpsellValuePropList(firstValueProp=" + this.a + ", secondValueProp=" + this.b + ", thirdValueProp=" + this.c + ")";
    }
}
