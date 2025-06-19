package com.quizlet.login.signup.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PromptParentEmailData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<PromptParentEmailData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(10);
    public final Map a;
    public final String b;
    public final com.quizlet.login.oldlogin.b c;

    public PromptParentEmailData(Map requestParams, String authProvider, com.quizlet.login.oldlogin.b requestType) {
        Intrinsics.checkNotNullParameter(requestParams, "requestParams");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        Intrinsics.checkNotNullParameter(requestType, "requestType");
        this.a = requestParams;
        this.b = authProvider;
        this.c = requestType;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PromptParentEmailData)) {
            return false;
        }
        PromptParentEmailData promptParentEmailData = (PromptParentEmailData) obj;
        return Intrinsics.b(this.a, promptParentEmailData.a) && Intrinsics.b(this.b, promptParentEmailData.b) && this.c == promptParentEmailData.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "PromptParentEmailData(requestParams=" + this.a + ", authProvider=" + this.b + ", requestType=" + this.c + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        Map map = this.a;
        dest.writeInt(map.size());
        for (Map.Entry entry : map.entrySet()) {
            dest.writeString((String) entry.getKey());
            dest.writeString((String) entry.getValue());
        }
        dest.writeString(this.b);
        dest.writeString(this.c.name());
    }
}
