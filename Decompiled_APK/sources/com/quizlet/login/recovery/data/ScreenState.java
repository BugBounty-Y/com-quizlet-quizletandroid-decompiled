package com.quizlet.login.recovery.data;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class ScreenState implements Parcelable {

    @Metadata
    public static final class KnownAccountExists extends ScreenState {

        @NotNull
        public static final Parcelable.Creator<KnownAccountExists> CREATOR = new a();
        public final String a;
        public final String b;
        public final String c;
        public final boolean d;

        public KnownAccountExists(String username, String email, String str, boolean z) {
            Intrinsics.checkNotNullParameter(username, "username");
            Intrinsics.checkNotNullParameter(email, "email");
            this.a = username;
            this.b = email;
            this.c = str;
            this.d = z;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof KnownAccountExists)) {
                return false;
            }
            KnownAccountExists knownAccountExists = (KnownAccountExists) obj;
            return Intrinsics.b(this.a, knownAccountExists.a) && Intrinsics.b(this.b, knownAccountExists.b) && Intrinsics.b(this.c, knownAccountExists.c) && this.d == knownAccountExists.d;
        }

        public final int hashCode() {
            int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
            String str = this.c;
            return Boolean.hashCode(this.d) + ((iE + (str == null ? 0 : str.hashCode())) * 31);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("KnownAccountExists(username=");
            sb.append(this.a);
            sb.append(", email=");
            sb.append(this.b);
            sb.append(", profileImageUrl=");
            sb.append(this.c);
            sb.append(", isUserPlus=");
            return android.support.v4.media.session.a.o(")", sb, this.d);
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
            dest.writeString(this.b);
            dest.writeString(this.c);
            dest.writeInt(this.d ? 1 : 0);
        }
    }

    @Metadata
    public static final class MultipleAccountsExist extends ScreenState {
        public static final MultipleAccountsExist a = new MultipleAccountsExist();

        @NotNull
        public static final Parcelable.Creator<MultipleAccountsExist> CREATOR = new b();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class UnknownAccountExists extends ScreenState {
        public static final UnknownAccountExists a = new UnknownAccountExists();

        @NotNull
        public static final Parcelable.Creator<UnknownAccountExists> CREATOR = new c();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }
}
