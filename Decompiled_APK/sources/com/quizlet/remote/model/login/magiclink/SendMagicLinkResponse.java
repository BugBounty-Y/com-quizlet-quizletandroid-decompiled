package com.quizlet.remote.model.login.magiclink;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SendMagicLinkResponse {
    public final boolean a;
    public final Errors b;

    public SendMagicLinkResponse(@InterfaceC4853h(name = "success") boolean z, @InterfaceC4853h(name = "errors") Errors errors) {
        this.a = z;
        this.b = errors;
    }

    @NotNull
    public final SendMagicLinkResponse copy(@InterfaceC4853h(name = "success") boolean z, @InterfaceC4853h(name = "errors") Errors errors) {
        return new SendMagicLinkResponse(z, errors);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SendMagicLinkResponse)) {
            return false;
        }
        SendMagicLinkResponse sendMagicLinkResponse = (SendMagicLinkResponse) obj;
        return this.a == sendMagicLinkResponse.a && Intrinsics.b(this.b, sendMagicLinkResponse.b);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        Errors errors = this.b;
        return iHashCode + (errors == null ? 0 : errors.hashCode());
    }

    public final String toString() {
        return "SendMagicLinkResponse(success=" + this.a + ", errors=" + this.b + ")";
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class Errors {
        public final String a;
        public final String b;

        public Errors(@InterfaceC4853h(name = "email") String str, @InterfaceC4853h(name = "generic") String str2) {
            this.a = str;
            this.b = str2;
        }

        @NotNull
        public final Errors copy(@InterfaceC4853h(name = "email") String str, @InterfaceC4853h(name = "generic") String str2) {
            return new Errors(str, str2);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Errors)) {
                return false;
            }
            Errors errors = (Errors) obj;
            return Intrinsics.b(this.a, errors.a) && Intrinsics.b(this.b, errors.b);
        }

        public final int hashCode() {
            String str = this.a;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            String str2 = this.b;
            return iHashCode + (str2 != null ? str2.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Errors(email=");
            sb.append(this.a);
            sb.append(", generic=");
            return android.support.v4.media.session.a.t(sb, this.b, ")");
        }

        public /* synthetic */ Errors(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2);
        }
    }

    public /* synthetic */ SendMagicLinkResponse(boolean z, Errors errors, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? false : z, (i & 2) != 0 ? null : errors);
    }
}
