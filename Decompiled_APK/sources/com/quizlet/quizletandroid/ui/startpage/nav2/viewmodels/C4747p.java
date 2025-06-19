package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import com.quizlet.data.model.EnumC4164s0;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4747p extends D {
    public final EnumC4164s0 a;

    public C4747p(EnumC4164s0 enumC4164s0) {
        this.a = enumC4164s0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4747p) && this.a == ((C4747p) obj).a;
    }

    public final int hashCode() {
        EnumC4164s0 enumC4164s0 = this.a;
        if (enumC4164s0 == null) {
            return 0;
        }
        return enumC4164s0.hashCode();
    }

    public final String toString() {
        return "GoToLibrary(tab=" + this.a + ")";
    }
}
