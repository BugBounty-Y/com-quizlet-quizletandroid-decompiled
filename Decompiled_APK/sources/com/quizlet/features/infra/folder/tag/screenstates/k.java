package com.quizlet.features.infra.folder.tag.screenstates;

import androidx.compose.animation.d0;
import com.quizlet.data.model.EnumC4159q0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k {
    public final kotlinx.collections.immutable.b a;
    public final EnumC4159q0 b;
    public final boolean c;
    public final kotlinx.collections.immutable.b d;
    public final boolean e;

    public k(kotlinx.collections.immutable.b tagsNames, EnumC4159q0 invalidInputType, boolean z, kotlinx.collections.immutable.b recommendedTagNames) {
        Intrinsics.checkNotNullParameter(tagsNames, "tagsNames");
        Intrinsics.checkNotNullParameter(invalidInputType, "invalidInputType");
        Intrinsics.checkNotNullParameter(recommendedTagNames, "recommendedTagNames");
        this.a = tagsNames;
        this.b = invalidInputType;
        this.c = z;
        this.d = recommendedTagNames;
        this.e = invalidInputType == EnumC4159q0.a;
    }

    public static k a(k kVar, kotlinx.collections.immutable.b tagsNames, EnumC4159q0 invalidInputType, boolean z, kotlinx.collections.immutable.b recommendedTagNames, int i) {
        if ((i & 1) != 0) {
            tagsNames = kVar.a;
        }
        if ((i & 2) != 0) {
            invalidInputType = kVar.b;
        }
        if ((i & 4) != 0) {
            z = kVar.c;
        }
        if ((i & 8) != 0) {
            recommendedTagNames = kVar.d;
        }
        kVar.getClass();
        Intrinsics.checkNotNullParameter(tagsNames, "tagsNames");
        Intrinsics.checkNotNullParameter(invalidInputType, "invalidInputType");
        Intrinsics.checkNotNullParameter(recommendedTagNames, "recommendedTagNames");
        return new k(tagsNames, invalidInputType, z, recommendedTagNames);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && this.b == kVar.b && this.c == kVar.c && Intrinsics.b(this.d, kVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "NewTagScreenState(tagsNames=" + this.a + ", invalidInputType=" + this.b + ", isUploadingTags=" + this.c + ", recommendedTagNames=" + this.d + ")";
    }

    public k(kotlinx.collections.immutable.e eVar, kotlinx.collections.immutable.e eVar2, int i) {
        this((i & 1) != 0 ? kotlinx.collections.immutable.implementations.immutableList.g.c : eVar, EnumC4159q0.a, false, (i & 8) != 0 ? kotlinx.collections.immutable.implementations.immutableList.g.c : eVar2);
    }
}
