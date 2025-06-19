package com.quizlet.features.infra.basestudy.data.models;

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
public final class MeteredValue implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<MeteredValue> CREATOR;
    public static final MeteredValue a;
    public static final MeteredValue b;
    public static final MeteredValue c;
    public static final /* synthetic */ MeteredValue[] d;

    static {
        MeteredValue meteredValue = new MeteredValue("UNMETERED_VARIANT", 0);
        a = meteredValue;
        MeteredValue meteredValue2 = new MeteredValue("METERED_VARIANT", 1);
        b = meteredValue2;
        MeteredValue meteredValue3 = new MeteredValue("UNMETERED_NONVARIANT", 2);
        c = meteredValue3;
        MeteredValue[] meteredValueArr = {meteredValue, meteredValue2, meteredValue3};
        d = meteredValueArr;
        AbstractC3328d.f(meteredValueArr);
        CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(1);
    }

    public static MeteredValue valueOf(String str) {
        return (MeteredValue) Enum.valueOf(MeteredValue.class, str);
    }

    public static MeteredValue[] values() {
        return (MeteredValue[]) d.clone();
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(name());
    }
}
