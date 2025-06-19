package com.quizlet.features.infra.basestudy.manager;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4519s1;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final EnumC4519s1 a;
    public final Long b;
    public final int c;
    public final EnumC4525u1 d;
    public final w1 e;
    public final int f;
    public final int g;
    public final String h;
    public final String i;
    public final com.quizlet.features.folders.logging.a j;

    public b(EnumC4519s1 action, Long l, int i, EnumC4525u1 placement, w1 subplacement, int i2, int i3, String str, String str2, com.quizlet.features.folders.logging.a modifier) {
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(placement, "placement");
        Intrinsics.checkNotNullParameter(subplacement, "subplacement");
        Intrinsics.checkNotNullParameter(modifier, "modifier");
        this.a = action;
        this.b = l;
        this.c = i;
        this.d = placement;
        this.e = subplacement;
        this.f = i2;
        this.g = i3;
        this.h = str;
        this.i = str2;
        this.j = modifier;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && this.c == bVar.c && this.d == bVar.d && this.e == bVar.e && this.f == bVar.f && this.g == bVar.g && Intrinsics.b(this.h, bVar.h) && Intrinsics.b(this.i, bVar.i) && this.j.equals(bVar.j);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Long l = this.b;
        int iB = d0.b(this.g, d0.b(this.f, (this.e.hashCode() + ((this.d.hashCode() + d0.b(this.c, (iHashCode + (l == null ? 0 : l.hashCode())) * 31, 31)) * 31)) * 31, 31), 31);
        String str = this.h;
        int iHashCode2 = (iB + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.i;
        return this.j.hashCode() + ((iHashCode2 + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "ImpressionsPayload(action=" + this.a + ", modelId=" + this.b + ", modelType=" + this.c + ", placement=" + this.d + ", subplacement=" + this.e + ", pageOrder=" + this.f + ", itemOrder=" + this.g + ", noteUuid=" + this.h + ", modelIdString=" + this.i + ", modifier=" + this.j + ")";
    }
}
