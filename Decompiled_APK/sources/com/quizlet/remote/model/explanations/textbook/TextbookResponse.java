package com.quizlet.remote.model.explanations.textbook;

import com.quizlet.remote.model.base.ApiResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class TextbookResponse extends ApiResponse {
    public final Models d;
    public final RemoteMeteringInfo e;

    @m(generateAdapter = true)
    @Metadata
    public static final class Models {
        public final List a;

        public Models(@InterfaceC4853h(name = "textbook") List<RemoteTextbook> list) {
            this.a = list;
        }

        @NotNull
        public final Models copy(@InterfaceC4853h(name = "textbook") List<RemoteTextbook> list) {
            return new Models(list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Models) && Intrinsics.b(this.a, ((Models) obj).a);
        }

        public final int hashCode() {
            List list = this.a;
            if (list == null) {
                return 0;
            }
            return list.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("Models(textbooks="), this.a);
        }
    }

    public TextbookResponse(@InterfaceC4853h(name = "models") Models models, @InterfaceC4853h(name = "metering") RemoteMeteringInfo remoteMeteringInfo) {
        this.d = models;
        this.e = remoteMeteringInfo;
    }

    @NotNull
    public final TextbookResponse copy(@InterfaceC4853h(name = "models") Models models, @InterfaceC4853h(name = "metering") RemoteMeteringInfo remoteMeteringInfo) {
        return new TextbookResponse(models, remoteMeteringInfo);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextbookResponse)) {
            return false;
        }
        TextbookResponse textbookResponse = (TextbookResponse) obj;
        return Intrinsics.b(this.d, textbookResponse.d) && Intrinsics.b(this.e, textbookResponse.e);
    }

    public final int hashCode() {
        Models models = this.d;
        int iHashCode = (models == null ? 0 : models.hashCode()) * 31;
        RemoteMeteringInfo remoteMeteringInfo = this.e;
        return iHashCode + (remoteMeteringInfo != null ? remoteMeteringInfo.hashCode() : 0);
    }

    public final String toString() {
        return "TextbookResponse(models=" + this.d + ", meteringInfo=" + this.e + ")";
    }
}
