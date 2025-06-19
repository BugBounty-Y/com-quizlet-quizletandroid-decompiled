package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.features.questionnaire.navigation.Control;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class StepModel implements Parcelable {

    @Metadata
    public static final class Exams extends StepModel {

        @NotNull
        public static final Parcelable.Creator<Exams> CREATOR = new r();
        public final String a;
        public final Progress b;
        public final Control.Button c;

        public Exams(String id, Progress progress, Control.Button control) {
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(progress, "progress");
            Intrinsics.checkNotNullParameter(control, "control");
            this.a = id;
            this.b = progress;
            this.c = control;
        }

        @Override // com.quizlet.features.questionnaire.navigation.StepModel
        public final Progress a() {
            return this.b;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Exams)) {
                return false;
            }
            Exams exams = (Exams) obj;
            return Intrinsics.b(this.a, exams.a) && Intrinsics.b(this.b, exams.b) && Intrinsics.b(this.c, exams.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
        }

        public final String toString() {
            return "Exams(id=" + this.a + ", progress=" + this.b + ", control=" + this.c + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            this.b.writeToParcel(dest, i);
            this.c.writeToParcel(dest, i);
        }
    }

    @Metadata
    public static final class Intro extends StepModel {

        @NotNull
        public static final Parcelable.Creator<Intro> CREATOR = new s();
        public final String a;
        public final Progress b;
        public final ArrayList c;
        public final Control.Button d;
        public final String e;
        public final String f;

        public Intro(String id, Progress progress, ArrayList control, Control.Button skip, String title, String subtitle) {
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(progress, "progress");
            Intrinsics.checkNotNullParameter(control, "control");
            Intrinsics.checkNotNullParameter(skip, "skip");
            Intrinsics.checkNotNullParameter(title, "title");
            Intrinsics.checkNotNullParameter(subtitle, "subtitle");
            this.a = id;
            this.b = progress;
            this.c = control;
            this.d = skip;
            this.e = title;
            this.f = subtitle;
        }

        @Override // com.quizlet.features.questionnaire.navigation.StepModel
        public final Progress a() {
            return this.b;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Intro)) {
                return false;
            }
            Intro intro = (Intro) obj;
            return Intrinsics.b(this.a, intro.a) && Intrinsics.b(this.b, intro.b) && this.c.equals(intro.c) && Intrinsics.b(this.d, intro.d) && Intrinsics.b(this.e, intro.e) && Intrinsics.b(this.f, intro.f);
        }

        public final int hashCode() {
            return this.f.hashCode() + d0.e((this.d.hashCode() + d0.h(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31)) * 31, 31, this.e);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Intro(id=");
            sb.append(this.a);
            sb.append(", progress=");
            sb.append(this.b);
            sb.append(", control=");
            sb.append(this.c);
            sb.append(", skip=");
            sb.append(this.d);
            sb.append(", title=");
            sb.append(this.e);
            sb.append(", subtitle=");
            return android.support.v4.media.session.a.t(sb, this.f, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            this.b.writeToParcel(dest, i);
            ArrayList arrayList = this.c;
            dest.writeInt(arrayList.size());
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((Control.Button) it2.next()).writeToParcel(dest, i);
            }
            this.d.writeToParcel(dest, i);
            dest.writeString(this.e);
            dest.writeString(this.f);
        }
    }

    @Metadata
    public static final class SchoolCourse extends StepModel {

        @NotNull
        public static final Parcelable.Creator<SchoolCourse> CREATOR = new t();
        public final String a;
        public final Progress b;
        public final Control.Button c;

        public SchoolCourse(String id, Progress progress, Control.Button control) {
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(progress, "progress");
            Intrinsics.checkNotNullParameter(control, "control");
            this.a = id;
            this.b = progress;
            this.c = control;
        }

        @Override // com.quizlet.features.questionnaire.navigation.StepModel
        public final Progress a() {
            return this.b;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof SchoolCourse)) {
                return false;
            }
            SchoolCourse schoolCourse = (SchoolCourse) obj;
            return Intrinsics.b(this.a, schoolCourse.a) && Intrinsics.b(this.b, schoolCourse.b) && Intrinsics.b(this.c, schoolCourse.c);
        }

        public final int hashCode() {
            return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
        }

        public final String toString() {
            return "SchoolCourse(id=" + this.a + ", progress=" + this.b + ", control=" + this.c + ")";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            this.b.writeToParcel(dest, i);
            this.c.writeToParcel(dest, i);
        }
    }

    public abstract Progress a();
}
