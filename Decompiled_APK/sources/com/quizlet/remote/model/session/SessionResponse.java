package com.quizlet.remote.model.session;

import android.support.v4.media.session.a;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SessionResponse extends ApiResponse {
    public final SessionModels d;

    @m(generateAdapter = true)
    @Metadata
    public static final class SessionModels {
        public final List a;

        public SessionModels(@InterfaceC4853h(name = "session") List<RemoteSession> list) {
            this.a = list;
        }

        @NotNull
        public final SessionModels copy(@InterfaceC4853h(name = "session") List<RemoteSession> list) {
            return new SessionModels(list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof SessionModels) && Intrinsics.b(this.a, ((SessionModels) obj).a);
        }

        public final int hashCode() {
            List list = this.a;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final String toString() {
            return a.n(")", new StringBuilder("SessionModels(session="), this.a);
        }
    }

    public SessionResponse(@InterfaceC4853h(name = "models") SessionModels sessionModels) {
        this.d = sessionModels;
    }

    @NotNull
    public final SessionResponse copy(@InterfaceC4853h(name = "models") SessionModels sessionModels) {
        return new SessionResponse(sessionModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SessionResponse) && Intrinsics.b(this.d, ((SessionResponse) obj).d);
    }

    public final int hashCode() {
        SessionModels sessionModels = this.d;
        if (sessionModels == null) {
            return 0;
        }
        return sessionModels.hashCode();
    }

    public final String toString() {
        return "SessionResponse(models=" + this.d + ")";
    }
}
