package com.quizlet.security.challenge.eventlogging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends com.quizlet.quizletandroid.ui.setcreation.tracking.a {
    public final String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(String urlPath) {
        super("challenge_received");
        Intrinsics.checkNotNullParameter(urlPath, "urlPath");
        this.b = urlPath;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.b, ((c) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ChallengeReceived(urlPath="), this.b, ")");
    }
}
