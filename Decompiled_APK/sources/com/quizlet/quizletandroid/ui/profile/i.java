package com.quizlet.quizletandroid.ui.profile;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends l {
    public final String a;
    public final boolean b;

    public i(String profileImageId, boolean z) {
        Intrinsics.checkNotNullParameter(profileImageId, "profileImageId");
        this.a = profileImageId;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && this.b == iVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GoToChangeProfileImage(profileImageId=" + this.a + ", shouldAllowCustomProfileImages=" + this.b + ")";
    }
}
