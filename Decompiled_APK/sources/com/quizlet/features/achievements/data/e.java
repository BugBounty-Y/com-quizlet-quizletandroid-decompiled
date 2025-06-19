package com.quizlet.features.achievements.data;

import com.quizlet.data.model.C4114c;
import com.quizlet.data.model.C4166t;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements h {
    public final C4166t a;
    public final kotlinx.collections.immutable.b b;
    public final kotlinx.collections.immutable.b c;
    public final kotlinx.collections.immutable.b d;
    public final kotlinx.collections.immutable.b e;
    public final kotlinx.collections.immutable.b f;
    public final kotlinx.collections.immutable.b g;
    public final C4114c h;

    public e(C4166t recents, kotlinx.collections.immutable.b study, kotlinx.collections.immutable.b daily, kotlinx.collections.immutable.b weekly, kotlinx.collections.immutable.b sets, kotlinx.collections.immutable.b rounds, kotlinx.collections.immutable.b solutions, C4114c c4114c) {
        Intrinsics.checkNotNullParameter(recents, "recents");
        Intrinsics.checkNotNullParameter(study, "study");
        Intrinsics.checkNotNullParameter(daily, "daily");
        Intrinsics.checkNotNullParameter(weekly, "weekly");
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(rounds, "rounds");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        this.a = recents;
        this.b = study;
        this.c = daily;
        this.d = weekly;
        this.e = sets;
        this.f = rounds;
        this.g = solutions;
        this.h = c4114c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d) && Intrinsics.b(this.e, eVar.e) && Intrinsics.b(this.f, eVar.f) && Intrinsics.b(this.g, eVar.g) && Intrinsics.b(this.h, eVar.h);
    }

    public final int hashCode() {
        int iHashCode = (this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31;
        C4114c c4114c = this.h;
        return iHashCode + (c4114c == null ? 0 : c4114c.hashCode());
    }

    public final String toString() {
        return "Loaded(recents=" + this.a + ", study=" + this.b + ", daily=" + this.c + ", weekly=" + this.d + ", sets=" + this.e + ", rounds=" + this.f + ", solutions=" + this.g + ", initialBadge=" + this.h + ")";
    }
}
