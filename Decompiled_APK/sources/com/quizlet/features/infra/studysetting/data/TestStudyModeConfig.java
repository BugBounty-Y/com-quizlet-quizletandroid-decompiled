package com.quizlet.features.infra.studysetting.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.O1;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TestStudyModeConfig implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<TestStudyModeConfig> CREATOR = new a(2);
    public final int a;
    public final List b;
    public final List c;
    public final HashSet d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;

    public TestStudyModeConfig(int i, List promptSides, List answerSides, HashSet enabledQuestionTypes, boolean z, boolean z2, boolean z3, boolean z4) {
        Intrinsics.checkNotNullParameter(promptSides, "promptSides");
        Intrinsics.checkNotNullParameter(answerSides, "answerSides");
        Intrinsics.checkNotNullParameter(enabledQuestionTypes, "enabledQuestionTypes");
        this.a = i;
        this.b = promptSides;
        this.c = answerSides;
        this.d = enabledQuestionTypes;
        this.e = z;
        this.f = z2;
        this.g = z3;
        this.h = z4;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TestStudyModeConfig)) {
            return false;
        }
        TestStudyModeConfig testStudyModeConfig = (TestStudyModeConfig) obj;
        return this.a == testStudyModeConfig.a && Intrinsics.b(this.b, testStudyModeConfig.b) && Intrinsics.b(this.c, testStudyModeConfig.c) && this.d.equals(testStudyModeConfig.d) && this.e == testStudyModeConfig.e && this.f == testStudyModeConfig.f && this.g == testStudyModeConfig.g && this.h == testStudyModeConfig.h;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.h) + d0.g(d0.g(d0.g((this.d.hashCode() + d0.f(d0.f(Integer.hashCode(this.a) * 31, 31, this.b), 31, this.c)) * 31, 31, this.e), 31, this.f), 31, this.g);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TestStudyModeConfig(questionCount=");
        sb.append(this.a);
        sb.append(", promptSides=");
        sb.append(this.b);
        sb.append(", answerSides=");
        sb.append(this.c);
        sb.append(", enabledQuestionTypes=");
        sb.append(this.d);
        sb.append(", instantFeedbackEnabled=");
        sb.append(this.e);
        sb.append(", tapToPlayAudioEnabled=");
        sb.append(this.f);
        sb.append(", partialAnswersEnabled=");
        sb.append(this.g);
        sb.append(", smartGradingEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.h);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        List list = this.b;
        dest.writeInt(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            dest.writeString(((O1) it2.next()).name());
        }
        List list2 = this.c;
        dest.writeInt(list2.size());
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            dest.writeString(((O1) it3.next()).name());
        }
        HashSet hashSet = this.d;
        dest.writeInt(hashSet.size());
        Iterator it4 = hashSet.iterator();
        while (it4.hasNext()) {
            dest.writeString(((com.quizlet.sharedconfig.study_setting_metadata.b) it4.next()).name());
        }
        dest.writeInt(this.e ? 1 : 0);
        dest.writeInt(this.f ? 1 : 0);
        dest.writeInt(this.g ? 1 : 0);
        dest.writeInt(this.h ? 1 : 0);
    }
}
