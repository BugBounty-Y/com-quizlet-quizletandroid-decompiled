package com.quizlet.features.infra.models.flashcards;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FlashcardSettings$FlashcardSettingsState implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<FlashcardSettings$FlashcardSettingsState> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(4);
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final long h;
    public final int i;

    public FlashcardSettings$FlashcardSettingsState(String str, String str2, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, long j, int i) {
        this.a = str;
        this.b = str2;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = z5;
        this.h = j;
        this.i = i;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardSettings$FlashcardSettingsState)) {
            return false;
        }
        FlashcardSettings$FlashcardSettingsState flashcardSettings$FlashcardSettingsState = (FlashcardSettings$FlashcardSettingsState) obj;
        return Intrinsics.b(this.a, flashcardSettings$FlashcardSettingsState.a) && Intrinsics.b(this.b, flashcardSettings$FlashcardSettingsState.b) && this.c == flashcardSettings$FlashcardSettingsState.c && this.d == flashcardSettings$FlashcardSettingsState.d && this.e == flashcardSettings$FlashcardSettingsState.e && this.f == flashcardSettings$FlashcardSettingsState.f && this.g == flashcardSettings$FlashcardSettingsState.g && this.h == flashcardSettings$FlashcardSettingsState.h && this.i == flashcardSettings$FlashcardSettingsState.i;
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return Integer.hashCode(this.i) + d0.d(d0.g(d0.g(d0.g(d0.g(d0.g((iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31, 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardSettingsState(frontSide=");
        sb.append(this.a);
        sb.append(", backSide=");
        sb.append(this.b);
        sb.append(", speakWordEnabled=");
        sb.append(this.c);
        sb.append(", speakDefEnabled=");
        sb.append(this.d);
        sb.append(", autoPlayEnabled=");
        sb.append(this.e);
        sb.append(", shuffleEnabled=");
        sb.append(this.f);
        sb.append(", selectedTermsMode=");
        sb.append(this.g);
        sb.append(", shuffleSeed=");
        sb.append(this.h);
        sb.append(", rawFlashcardMode=");
        return android.support.v4.media.session.a.r(sb, this.i, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeString(this.b);
        dest.writeInt(this.c ? 1 : 0);
        dest.writeInt(this.d ? 1 : 0);
        dest.writeInt(this.e ? 1 : 0);
        dest.writeInt(this.f ? 1 : 0);
        dest.writeInt(this.g ? 1 : 0);
        dest.writeLong(this.h);
        dest.writeInt(this.i);
    }
}
