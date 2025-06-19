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
public final class StudiableMetadataType implements serialization.b, Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableMetadataType> CREATOR;
    public static final /* synthetic */ StudiableMetadataType[] b;
    public final int a;

    static {
        StudiableMetadataType[] studiableMetadataTypeArr = {new StudiableMetadataType("ALTERNATIVE_QUESTIONS", 0, 1), new StudiableMetadataType("FILL_IN_THE_BLANK_KEYPHRASES", 1, 2), new StudiableMetadataType("ITEM_DIFFICULTY", 2, 3), new StudiableMetadataType("ML_DISTRACTORS", 3, 4), new StudiableMetadataType("CARD_SIDE_QUESTION_TYPE_RECOMMENDATIONS", 4, 5), new StudiableMetadataType("PARSED_MULTIPLE_CHOICE_QUESTION", 5, 6), new StudiableMetadataType("CARD_EXPLANATIONS", 6, 7), new StudiableMetadataType("MCQ_EXPLANATIONS", 7, 8), new StudiableMetadataType("MULTIPLE_CHOICE_SELECT_ALL_THAT_APPLY", 8, 9), new StudiableMetadataType("FILL_IN_THE_BLANK_MULTIPLE_CHOICE", 9, 10)};
        b = studiableMetadataTypeArr;
        AbstractC3328d.f(studiableMetadataTypeArr);
        CREATOR = new f(9);
    }

    public StudiableMetadataType(String str, int i, int i2) {
        this.a = i2;
    }

    public static StudiableMetadataType valueOf(String str) {
        return (StudiableMetadataType) Enum.valueOf(StudiableMetadataType.class, str);
    }

    public static StudiableMetadataType[] values() {
        return (StudiableMetadataType[]) b.clone();
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
