package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j {
    public final boolean a;
    public final Function1 b;

    public j(Function1 checkListener, boolean z) {
        Intrinsics.checkNotNullParameter(checkListener, "checkListener");
        this.a = z;
        this.b = checkListener;
    }

    public static j a(j jVar, boolean z) {
        Function1 checkListener = jVar.b;
        jVar.getClass();
        Intrinsics.checkNotNullParameter(checkListener, "checkListener");
        return new j(checkListener, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "SwitchData(isChecked=" + this.a + ", checkListener=" + this.b + ")";
    }
}
