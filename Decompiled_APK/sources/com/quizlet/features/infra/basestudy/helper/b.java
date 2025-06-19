package com.quizlet.features.infra.basestudy.helper;

import assistantMode.enums.m;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final m a;
    public final m b;
    public final Boolean c;
    public final Long d;

    public b(m mVar, m mVar2, Boolean bool, Long l) {
        this.a = mVar;
        this.b = mVar2;
        this.c = bool;
        this.d = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d);
    }

    public final int hashCode() {
        m mVar = this.a;
        int iHashCode = (mVar == null ? 0 : mVar.hashCode()) * 31;
        m mVar2 = this.b;
        int iHashCode2 = (iHashCode + (mVar2 == null ? 0 : mVar2.hashCode())) * 31;
        Boolean bool = this.c;
        int iHashCode3 = (iHashCode2 + (bool == null ? 0 : bool.hashCode())) * 31;
        Long l = this.d;
        return iHashCode3 + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "FlashcardsSettingsToMigrate(promptSide=" + this.a + ", answerSide=" + this.b + ", sortingEnabled=" + this.c + ", shuffleSeed=" + this.d + ")";
    }
}
