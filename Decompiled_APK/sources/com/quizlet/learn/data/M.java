package com.quizlet.learn.data;

import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalButtonState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class M extends N {
    public final com.quizlet.qutils.string.f a;
    public final com.quizlet.qutils.string.d b;
    public final com.quizlet.qutils.string.f c;
    public final com.quizlet.learn.viewmodel.k d;

    public M(com.quizlet.qutils.string.f header, com.quizlet.qutils.string.d description, com.quizlet.qutils.string.f ctaText, com.quizlet.learn.viewmodel.k ctaAction) {
        InfoModalButtonState.Primary buttonState = InfoModalButtonState.Primary.a;
        Intrinsics.checkNotNullParameter(header, "header");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(ctaText, "ctaText");
        Intrinsics.checkNotNullParameter(buttonState, "buttonState");
        Intrinsics.checkNotNullParameter(ctaAction, "ctaAction");
        this.a = header;
        this.b = description;
        this.c = ctaText;
        this.d = ctaAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof M)) {
            return false;
        }
        M m = (M) obj;
        if (!this.a.equals(m.a) || !this.b.equals(m.b) || !this.c.equals(m.c)) {
            return false;
        }
        Object obj2 = InfoModalButtonState.Primary.a;
        return obj2.equals(obj2) && this.d.equals(m.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((InfoModalButtonState.Primary.a.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ShowInfoModal(header=" + this.a + ", description=" + this.b + ", ctaText=" + this.c + ", buttonState=" + InfoModalButtonState.Primary.a + ", ctaAction=" + this.d + ")";
    }
}
