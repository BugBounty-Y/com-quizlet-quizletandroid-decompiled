package com.quizlet.features.home.data;

import com.quizlet.data.model.v2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements u {
    public final v2 a;
    public final boolean b;

    public s(v2 userProfileAvatarData, boolean z) {
        Intrinsics.checkNotNullParameter(userProfileAvatarData, "userProfileAvatarData");
        this.a = userProfileAvatarData;
        this.b = z;
    }

    @Override // com.quizlet.features.home.data.u
    public final v2 a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Intrinsics.b(this.a, sVar.a) && this.b == sVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Content(userProfileAvatarData=" + this.a + ", homeFeedShowProgress=" + this.b + ")";
    }
}
