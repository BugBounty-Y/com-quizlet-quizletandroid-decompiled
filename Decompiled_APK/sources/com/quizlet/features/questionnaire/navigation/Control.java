package com.quizlet.features.questionnaire.navigation;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class Control implements Parcelable {

    @Metadata
    public static final class Button extends Control {

        @NotNull
        public static final Parcelable.Creator<Button> CREATOR = new a();
        public final String a;
        public final String b;
        public final String c;
        public final String d;
        public final String e;

        public Button(String label, String str, String str2, String type, String payload) {
            Intrinsics.checkNotNullParameter(label, "label");
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(payload, "payload");
            this.a = label;
            this.b = str;
            this.c = str2;
            this.d = type;
            this.e = payload;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Button)) {
                return false;
            }
            Button button = (Button) obj;
            return Intrinsics.b(this.a, button.a) && Intrinsics.b(this.b, button.b) && Intrinsics.b(this.c, button.c) && Intrinsics.b(this.d, button.d) && Intrinsics.b(this.e, button.e);
        }

        public final int hashCode() {
            int iHashCode = this.a.hashCode() * 31;
            String str = this.b;
            int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
            String str2 = this.c;
            return this.e.hashCode() + d0.e((iHashCode2 + (str2 != null ? str2.hashCode() : 0)) * 31, 31, this.d);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("Button(label=");
            sb.append(this.a);
            sb.append(", iconName=");
            sb.append(this.b);
            sb.append(", goToStep=");
            sb.append(this.c);
            sb.append(", type=");
            sb.append(this.d);
            sb.append(", payload=");
            return android.support.v4.media.session.a.t(sb, this.e, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            dest.writeString(this.b);
            dest.writeString(this.c);
            dest.writeString(this.d);
            dest.writeString(this.e);
        }
    }
}
