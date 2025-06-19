package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.learn.settings.data.WrittenQuestionGradingOption;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class LearnSettingsUpdateData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<LearnSettingsUpdateData> CREATOR = new com.onetrust.otpublishers.headless.UI.DataModels.f(15);
    public final boolean a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final boolean i;
    public final boolean j;
    public final boolean k;
    public final WrittenQuestionGradingOption l;

    public LearnSettingsUpdateData(boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8, boolean z9, boolean z10, boolean z11, WrittenQuestionGradingOption writtenQuestionGradingOption) {
        Intrinsics.checkNotNullParameter(writtenQuestionGradingOption, "writtenQuestionGradingOption");
        this.a = z;
        this.b = z2;
        this.c = z3;
        this.d = z4;
        this.e = z5;
        this.f = z6;
        this.g = z7;
        this.h = z8;
        this.i = z9;
        this.j = z10;
        this.k = z11;
        this.l = writtenQuestionGradingOption;
    }

    public static LearnSettingsUpdateData a(LearnSettingsUpdateData learnSettingsUpdateData, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8, boolean z9, WrittenQuestionGradingOption writtenQuestionGradingOption, int i) {
        boolean z10 = (i & 1) != 0 ? learnSettingsUpdateData.a : z;
        boolean z11 = (i & 2) != 0 ? learnSettingsUpdateData.b : z2;
        boolean z12 = (i & 4) != 0 ? learnSettingsUpdateData.c : z3;
        boolean z13 = (i & 8) != 0 ? learnSettingsUpdateData.d : z4;
        boolean z14 = (i & 16) != 0 ? learnSettingsUpdateData.e : z5;
        boolean z15 = (i & 32) != 0 ? learnSettingsUpdateData.f : z6;
        boolean z16 = (i & 64) != 0 ? learnSettingsUpdateData.g : z7;
        boolean z17 = (i & 128) != 0 ? learnSettingsUpdateData.h : z8;
        boolean z18 = (i & 256) != 0 ? learnSettingsUpdateData.i : z9;
        boolean z19 = (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? learnSettingsUpdateData.j : true;
        boolean z20 = (i & 1024) != 0 ? learnSettingsUpdateData.k : true;
        WrittenQuestionGradingOption writtenQuestionGradingOption2 = (i & 2048) != 0 ? learnSettingsUpdateData.l : writtenQuestionGradingOption;
        learnSettingsUpdateData.getClass();
        Intrinsics.checkNotNullParameter(writtenQuestionGradingOption2, "writtenQuestionGradingOption");
        return new LearnSettingsUpdateData(z10, z11, z12, z13, z14, z15, z16, z17, z18, z19, z20, writtenQuestionGradingOption2);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LearnSettingsUpdateData)) {
            return false;
        }
        LearnSettingsUpdateData learnSettingsUpdateData = (LearnSettingsUpdateData) obj;
        return this.a == learnSettingsUpdateData.a && this.b == learnSettingsUpdateData.b && this.c == learnSettingsUpdateData.c && this.d == learnSettingsUpdateData.d && this.e == learnSettingsUpdateData.e && this.f == learnSettingsUpdateData.f && this.g == learnSettingsUpdateData.g && this.h == learnSettingsUpdateData.h && this.i == learnSettingsUpdateData.i && this.j == learnSettingsUpdateData.j && this.k == learnSettingsUpdateData.k && Intrinsics.b(this.l, learnSettingsUpdateData.l);
    }

    public final int hashCode() {
        return this.l.hashCode() + d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k);
    }

    public final String toString() {
        return "LearnSettingsUpdateData(shuffleEnabled=" + this.a + ", audioEnabled=" + this.b + ", retypeEnabled=" + this.c + ", answerWithTermEnabled=" + this.d + ", answerWithDefinitionEnabled=" + this.e + ", answerWithLocationEnabled=" + this.f + ", showFlashcardsEnabled=" + this.g + ", showMultipleChoiceQuestionsEnabled=" + this.h + ", showWrittenQuestionsEnabled=" + this.i + ", guidanceChanged=" + this.j + ", shouldGoToWriteMode=" + this.k + ", writtenQuestionGradingOption=" + this.l + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a ? 1 : 0);
        dest.writeInt(this.b ? 1 : 0);
        dest.writeInt(this.c ? 1 : 0);
        dest.writeInt(this.d ? 1 : 0);
        dest.writeInt(this.e ? 1 : 0);
        dest.writeInt(this.f ? 1 : 0);
        dest.writeInt(this.g ? 1 : 0);
        dest.writeInt(this.h ? 1 : 0);
        dest.writeInt(this.i ? 1 : 0);
        dest.writeInt(this.j ? 1 : 0);
        dest.writeInt(this.k ? 1 : 0);
        dest.writeParcelable(this.l, i);
    }
}
