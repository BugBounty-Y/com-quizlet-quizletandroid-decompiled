package com.quizlet.ads.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public abstract class AdDataType implements Parcelable {
    public final d a;

    @Metadata
    public static final class BannerAdType extends AdDataType {
        public static final BannerAdType b = new BannerAdType(d.a);

        @NotNull
        public static final Parcelable.Creator<BannerAdType> CREATOR = new b();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class CustomAdType extends AdDataType {

        @NotNull
        public static final Parcelable.Creator<CustomAdType> CREATOR = new c();
        public final d b;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public CustomAdType(d customAdType) {
            super(customAdType);
            Intrinsics.checkNotNullParameter(customAdType, "customAdType");
            this.b = customAdType;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof CustomAdType) && this.b == ((CustomAdType) obj).b;
        }

        public final int hashCode() {
            return this.b.hashCode();
        }

        public final String toString() {
            return "CustomAdType(customAdType=" + this.b + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.b.name());
        }
    }

    public AdDataType(d dVar) {
        this.a = dVar;
    }
}
