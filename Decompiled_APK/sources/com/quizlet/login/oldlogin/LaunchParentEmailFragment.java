package com.quizlet.login.oldlogin;

import androidx.compose.animation.d0;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LaunchParentEmailFragment extends c {
    public final HashMap a;
    public final String b;
    public final b c;

    public LaunchParentEmailFragment(HashMap request, String authProvider, b requestType) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        Intrinsics.checkNotNullParameter(requestType, "requestType");
        this.a = request;
        this.b = authProvider;
        this.c = requestType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LaunchParentEmailFragment)) {
            return false;
        }
        LaunchParentEmailFragment launchParentEmailFragment = (LaunchParentEmailFragment) obj;
        return this.a.equals(launchParentEmailFragment.a) && Intrinsics.b(this.b, launchParentEmailFragment.b) && this.c == launchParentEmailFragment.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "LaunchParentEmailFragment(request=" + this.a + ", authProvider=" + this.b + ", requestType=" + this.c + ")";
    }
}
