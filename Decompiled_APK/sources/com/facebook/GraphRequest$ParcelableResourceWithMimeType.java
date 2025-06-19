package com.facebook;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class GraphRequest$ParcelableResourceWithMimeType<RESOURCE extends Parcelable> implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<GraphRequest$ParcelableResourceWithMimeType<?>> CREATOR = new android.support.v4.media.a(14);
    public final String a;
    public final Parcelable b;

    public GraphRequest$ParcelableResourceWithMimeType(Parcelable parcelable) {
        this.a = "image/png";
        this.b = parcelable;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 1;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel out, int i) {
        Intrinsics.checkNotNullParameter(out, "out");
        out.writeString(this.a);
        out.writeParcelable(this.b, i);
    }

    public GraphRequest$ParcelableResourceWithMimeType(Parcel parcel) {
        this.a = parcel.readString();
        this.b = parcel.readParcelable(o.a().getClassLoader());
    }
}
