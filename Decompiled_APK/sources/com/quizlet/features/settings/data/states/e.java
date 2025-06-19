package com.quizlet.features.settings.data.states;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements h {
    public final com.quizlet.qutils.string.g a;
    public final com.quizlet.qutils.string.g b;
    public final com.quizlet.qutils.string.g c;

    public e(com.quizlet.qutils.string.g gVar, com.quizlet.qutils.string.f fVar, com.quizlet.features.settings.data.models.g gVar2, int i) {
        fVar = (i & 2) != 0 ? null : fVar;
        gVar2 = (i & 4) != 0 ? null : gVar2;
        this.a = gVar;
        this.b = fVar;
        this.c = gVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c);
    }

    public final int hashCode() {
        com.quizlet.qutils.string.g gVar = this.a;
        int iHashCode = (gVar == null ? 0 : gVar.hashCode()) * 31;
        com.quizlet.qutils.string.g gVar2 = this.b;
        int iHashCode2 = (iHashCode + (gVar2 == null ? 0 : gVar2.hashCode())) * 31;
        com.quizlet.qutils.string.g gVar3 = this.c;
        return iHashCode2 + (gVar3 != null ? gVar3.hashCode() : 0);
    }

    public final String toString() {
        return "Error(newPasswordError=" + this.a + ", confirmPasswordError=" + this.b + ", currentPasswordError=" + this.c + ")";
    }
}
