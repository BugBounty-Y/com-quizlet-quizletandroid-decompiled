package com.quizlet.login.oldlogin;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LaunchBirthdayFragment extends c {
    public final String a;
    public final String b;

    public LaunchBirthdayFragment(String data, String authProvider) {
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        this.a = data;
        this.b = authProvider;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LaunchBirthdayFragment)) {
            return false;
        }
        LaunchBirthdayFragment launchBirthdayFragment = (LaunchBirthdayFragment) obj;
        return Intrinsics.b(this.a, launchBirthdayFragment.a) && Intrinsics.b(this.b, launchBirthdayFragment.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LaunchBirthdayFragment(data=");
        sb.append(this.a);
        sb.append(", authProvider=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
