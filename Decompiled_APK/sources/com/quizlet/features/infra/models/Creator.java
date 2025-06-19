package com.quizlet.features.infra.models;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class Creator implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<Creator> CREATOR = new f(3);
    public final long a;
    public final String b;
    public final String c;
    public final int d;
    public final boolean e;
    public final boolean f;

    public Creator(int i, long j, String userName, String imageUrl, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(userName, "userName");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = j;
        this.b = userName;
        this.c = imageUrl;
        this.d = i;
        this.e = z;
        this.f = z2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Creator)) {
            return false;
        }
        Creator creator = (Creator) obj;
        return this.a == creator.a && Intrinsics.b(this.b, creator.b) && Intrinsics.b(this.c, creator.c) && this.d == creator.d && this.e == creator.e && this.f == creator.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.g(d0.b(this.d, d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Creator(creatorId=");
        sb.append(this.a);
        sb.append(", userName=");
        sb.append(this.b);
        sb.append(", imageUrl=");
        sb.append(this.c);
        sb.append(", creatorBadgeText=");
        sb.append(this.d);
        sb.append(", isVerified=");
        sb.append(this.e);
        sb.append(", isDeleted=");
        return android.support.v4.media.session.a.o(")", sb, this.f);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        dest.writeString(this.b);
        dest.writeString(this.c);
        dest.writeInt(this.d);
        dest.writeInt(this.e ? 1 : 0);
        dest.writeInt(this.f ? 1 : 0);
    }
}
