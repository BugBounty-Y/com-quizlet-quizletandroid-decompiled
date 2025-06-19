package com.quizlet.features.userprofile.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends h {
    public final String a;
    public final boolean b;

    public e(String profileImageId, boolean z) {
        Intrinsics.checkNotNullParameter(profileImageId, "profileImageId");
        this.a = profileImageId;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GoToChangeImage(profileImageId=" + this.a + ", shouldAllowCustomProfileImages=" + this.b + ")";
    }
}
