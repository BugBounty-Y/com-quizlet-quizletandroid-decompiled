package com.quizlet.learn.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class WrittenQuestionGradingOption implements Parcelable {
    public final int a;
    public final int b;
    public final boolean c;
    public final boolean d;

    @Metadata
    public static final class Moderate extends WrittenQuestionGradingOption {
        public static final Moderate e = new Moderate(R.string.learn_settings_written_grading_moderate_title, R.string.learn_settings_written_grading_moderate_description, true, false);

        @NotNull
        public static final Parcelable.Creator<Moderate> CREATOR = new c();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Moderate);
        }

        public final int hashCode() {
            return -1295077715;
        }

        public final String toString() {
            return "Moderate";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Relaxed extends WrittenQuestionGradingOption {
        public static final Relaxed e = new Relaxed(R.string.learn_settings_written_grading_relaxed_title, R.string.learn_settings_written_grading_relaxed_description, true, true);

        @NotNull
        public static final Parcelable.Creator<Relaxed> CREATOR = new d();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Relaxed);
        }

        public final int hashCode() {
            return -455336891;
        }

        public final String toString() {
            return "Relaxed";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Strict extends WrittenQuestionGradingOption {
        public static final Strict e = new Strict(R.string.learn_settings_written_grading_strict_title, R.string.learn_settings_written_grading_strict_description, false, false);

        @NotNull
        public static final Parcelable.Creator<Strict> CREATOR = new e();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Strict);
        }

        public final int hashCode() {
            return 1136358131;
        }

        public final String toString() {
            return "Strict";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    public WrittenQuestionGradingOption(int i, int i2, boolean z, boolean z2) {
        this.a = i;
        this.b = i2;
        this.c = z;
        this.d = z2;
    }
}
