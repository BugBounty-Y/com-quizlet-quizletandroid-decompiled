package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4748q extends D {
    public final String a;

    public C4748q(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.a = uuid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4748q) && Intrinsics.b(this.a, ((C4748q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GoToMagicNotes(uuid="), this.a, ")");
    }
}
