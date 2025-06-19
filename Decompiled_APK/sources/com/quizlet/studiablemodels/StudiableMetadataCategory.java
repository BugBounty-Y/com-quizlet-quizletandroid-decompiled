package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
@Metadata
/* loaded from: classes3.dex */
public final class StudiableMetadataCategory implements serialization.b, Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableMetadataCategory> CREATOR;
    public static final /* synthetic */ StudiableMetadataCategory[] b;
    public final int a;

    static {
        StudiableMetadataCategory[] studiableMetadataCategoryArr = {new StudiableMetadataCategory("REWORDING", 0, 1), new StudiableMetadataCategory("CONTEXT", 1, 2)};
        b = studiableMetadataCategoryArr;
        AbstractC3328d.f(studiableMetadataCategoryArr);
        CREATOR = new f(8);
    }

    public StudiableMetadataCategory(String str, int i, int i2) {
        this.a = i2;
    }

    public static StudiableMetadataCategory valueOf(String str) {
        return (StudiableMetadataCategory) Enum.valueOf(StudiableMetadataCategory.class, str);
    }

    public static StudiableMetadataCategory[] values() {
        return (StudiableMetadataCategory[]) b.clone();
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // serialization.b
    public final Integer getValue() {
        return Integer.valueOf(this.a);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(name());
    }
}
