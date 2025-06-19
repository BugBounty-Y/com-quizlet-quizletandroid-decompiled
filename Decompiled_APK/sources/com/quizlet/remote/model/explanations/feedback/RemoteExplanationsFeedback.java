package com.quizlet.remote.model.explanations.feedback;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteExplanationsFeedback {
    public final String a;
    public final String b;
    public final String c;

    public RemoteExplanationsFeedback(@InterfaceC4853h(name = "content_url") @NotNull String contentUrl, @InterfaceC4853h(name = "screen_size") @NotNull String screenSize, @InterfaceC4853h(name = "feedbackContent") String str) {
        Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
        Intrinsics.checkNotNullParameter(screenSize, "screenSize");
        this.a = contentUrl;
        this.b = screenSize;
        this.c = str;
    }

    @NotNull
    public final RemoteExplanationsFeedback copy(@InterfaceC4853h(name = "content_url") @NotNull String contentUrl, @InterfaceC4853h(name = "screen_size") @NotNull String screenSize, @InterfaceC4853h(name = "feedbackContent") String str) {
        Intrinsics.checkNotNullParameter(contentUrl, "contentUrl");
        Intrinsics.checkNotNullParameter(screenSize, "screenSize");
        return new RemoteExplanationsFeedback(contentUrl, screenSize, str);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteExplanationsFeedback)) {
            return false;
        }
        RemoteExplanationsFeedback remoteExplanationsFeedback = (RemoteExplanationsFeedback) obj;
        return Intrinsics.b(this.a, remoteExplanationsFeedback.a) && Intrinsics.b(this.b, remoteExplanationsFeedback.b) && Intrinsics.b(this.c, remoteExplanationsFeedback.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteExplanationsFeedback(contentUrl=");
        sb.append(this.a);
        sb.append(", screenSize=");
        sb.append(this.b);
        sb.append(", feedbackContent=");
        return a.t(sb, this.c, ")");
    }
}
