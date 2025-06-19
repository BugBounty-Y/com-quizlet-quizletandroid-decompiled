package com.quizlet.remote.model.studiableitem;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteCustomTextDistractor {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;

    public RemoteCustomTextDistractor(String plainText, String languageCode, String str, String str2, String str3) {
        Intrinsics.checkNotNullParameter(plainText, "plainText");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = plainText;
        this.b = languageCode;
        this.c = str;
        this.d = str2;
        this.e = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteCustomTextDistractor)) {
            return false;
        }
        RemoteCustomTextDistractor remoteCustomTextDistractor = (RemoteCustomTextDistractor) obj;
        return Intrinsics.b(this.a, remoteCustomTextDistractor.a) && Intrinsics.b(this.b, remoteCustomTextDistractor.b) && Intrinsics.b(this.c, remoteCustomTextDistractor.c) && Intrinsics.b(this.d, remoteCustomTextDistractor.d) && Intrinsics.b(this.e, remoteCustomTextDistractor.e);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteCustomTextDistractor(plainText=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", ttsUrl=");
        sb.append(this.c);
        sb.append(", ttsSlowUrl=");
        sb.append(this.d);
        sb.append(", richText=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
