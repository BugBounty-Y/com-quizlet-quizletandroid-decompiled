package com.quizlet.learn.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface LearnSettingsResult extends Parcelable {

    @Metadata
    public static final class NotUpdated implements LearnSettingsResult {
        public static final NotUpdated a = new NotUpdated();

        @NotNull
        public static final Parcelable.Creator<NotUpdated> CREATOR = new a();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof NotUpdated);
        }

        public final int hashCode() {
            return 1163726602;
        }

        public final String toString() {
            return "NotUpdated";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Updated implements LearnSettingsResult {

        @NotNull
        public static final Parcelable.Creator<Updated> CREATOR = new b();
        public final QuestionSettings a;
        public final boolean b;
        public final boolean c;
        public final boolean d;
        public final boolean e;
        public final boolean f;

        public Updated(QuestionSettings newSettings, boolean z, boolean z2, boolean z3, boolean z4, boolean z5) {
            Intrinsics.checkNotNullParameter(newSettings, "newSettings");
            this.a = newSettings;
            this.b = z;
            this.c = z2;
            this.d = z3;
            this.e = z4;
            this.f = z5;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Updated)) {
                return false;
            }
            Updated updated = (Updated) obj;
            return Intrinsics.b(this.a, updated.a) && this.b == updated.b && this.c == updated.c && this.d == updated.d && this.e == updated.e && this.f == updated.f;
        }

        public final int hashCode() {
            return Boolean.hashCode(this.f) + d0.g(d0.g(d0.g(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Updated(newSettings=");
            sb.append(this.a);
            sb.append(", audioChanged=");
            sb.append(this.b);
            sb.append(", shouldGenerateNewPrompt=");
            sb.append(this.c);
            sb.append(", guidanceChanged=");
            sb.append(this.d);
            sb.append(", isRestarting=");
            sb.append(this.e);
            sb.append(", shouldGoToWriteMode=");
            return android.support.v4.media.session.a.o(")", sb, this.f);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeParcelable(this.a, i);
            dest.writeInt(this.b ? 1 : 0);
            dest.writeInt(this.c ? 1 : 0);
            dest.writeInt(this.d ? 1 : 0);
            dest.writeInt(this.e ? 1 : 0);
            dest.writeInt(this.f ? 1 : 0);
        }
    }
}
