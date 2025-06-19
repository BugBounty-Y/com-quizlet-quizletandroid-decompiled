package com.quizlet.data.model;

import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class l2 {
    public final ArrayList a;
    public final ArrayList b;
    public final ArrayList c;
    public final Object d;

    public l2(ArrayList classSets, ArrayList sets, ArrayList sessions, List users) {
        Intrinsics.checkNotNullParameter(classSets, "classSets");
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(sessions, "sessions");
        Intrinsics.checkNotNullParameter(users, "users");
        this.a = classSets;
        this.b = sets;
        this.c = sessions;
        this.d = users;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l2)) {
            return false;
        }
        l2 l2Var = (l2) obj;
        return this.a.equals(l2Var.a) && this.b.equals(l2Var.b) && this.c.equals(l2Var.c) && Intrinsics.b(this.d, l2Var.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + androidx.compose.animation.d0.h(this.c, androidx.compose.animation.d0.h(this.b, this.a.hashCode() * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UniversalUploadFlowFlashcardSets(classSets=");
        sb.append(this.a);
        sb.append(", sets=");
        sb.append(this.b);
        sb.append(", sessions=");
        sb.append(this.c);
        sb.append(", users=");
        return android.support.v4.media.session.a.s(sb, this.d, ")");
    }
}
