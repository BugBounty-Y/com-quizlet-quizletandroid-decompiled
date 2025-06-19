package com.quizlet.remote.model.folder;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderCopyEligibilityResponse {
    public final Boolean a;

    public FolderCopyEligibilityResponse(Boolean bool) {
        this.a = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderCopyEligibilityResponse) && Intrinsics.b(this.a, ((FolderCopyEligibilityResponse) obj).a);
    }

    public final int hashCode() {
        Boolean bool = this.a;
        if (bool == null) {
            return 0;
        }
        return bool.hashCode();
    }

    public final String toString() {
        return "FolderCopyEligibilityResponse(isUserEligibleToCopyFolder=" + this.a + ")";
    }
}
