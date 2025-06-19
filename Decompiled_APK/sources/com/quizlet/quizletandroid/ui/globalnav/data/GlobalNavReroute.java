package com.quizlet.quizletandroid.ui.globalnav.data;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class GlobalNavReroute implements Parcelable {

    @Metadata
    public static final class Account extends GlobalNavReroute {
        public static final Account a = new Account();

        @NotNull
        public static final Parcelable.Creator<Account> CREATOR = new a();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Account);
        }

        public final int hashCode() {
            return 97831105;
        }

        public final String toString() {
            return "Account";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class AchievementsProfile extends GlobalNavReroute {

        @NotNull
        public static final Parcelable.Creator<AchievementsProfile> CREATOR = new b();
        public final long a;
        public final String b;

        public AchievementsProfile(long j, String str) {
            this.a = j;
            this.b = str;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof AchievementsProfile)) {
                return false;
            }
            AchievementsProfile achievementsProfile = (AchievementsProfile) obj;
            return this.a == achievementsProfile.a && Intrinsics.b(this.b, achievementsProfile.b);
        }

        public final int hashCode() {
            int iHashCode = Long.hashCode(this.a) * 31;
            String str = this.b;
            return iHashCode + (str == null ? 0 : str.hashCode());
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("AchievementsProfile(userId=");
            sb.append(this.a);
            sb.append(", badgeId=");
            return android.support.v4.media.session.a.t(sb, this.b, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeLong(this.a);
            dest.writeString(this.b);
        }
    }

    @Metadata
    public static final class ActivityCenter extends GlobalNavReroute {
        public static final ActivityCenter a = new ActivityCenter();

        @NotNull
        public static final Parcelable.Creator<ActivityCenter> CREATOR = new c();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof ActivityCenter);
        }

        public final int hashCode() {
            return 1288296240;
        }

        public final String toString() {
            return "ActivityCenter";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class CreateSet extends GlobalNavReroute {
        public static final CreateSet a = new CreateSet();

        @NotNull
        public static final Parcelable.Creator<CreateSet> CREATOR = new d();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof CreateSet);
        }

        public final int hashCode() {
            return 1951800154;
        }

        public final String toString() {
            return "CreateSet";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class EdgyDataCollection extends GlobalNavReroute {
        public static final EdgyDataCollection a = new EdgyDataCollection();

        @NotNull
        public static final Parcelable.Creator<EdgyDataCollection> CREATOR = new e();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof EdgyDataCollection);
        }

        public final int hashCode() {
            return -248823035;
        }

        public final String toString() {
            return "EdgyDataCollection";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Home extends GlobalNavReroute {
        public static final Home a = new Home();

        @NotNull
        public static final Parcelable.Creator<Home> CREATOR = new f();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Home);
        }

        public final int hashCode() {
            return -365535541;
        }

        public final String toString() {
            return "Home";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Library extends GlobalNavReroute {
        public static final Library a = new Library();

        @NotNull
        public static final Parcelable.Creator<Library> CREATOR = new g();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof Library);
        }

        public final int hashCode() {
            return 1441358671;
        }

        public final String toString() {
            return "Library";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class Search extends GlobalNavReroute {

        @NotNull
        public static final Parcelable.Creator<Search> CREATOR = new h();
        public final String a;

        public Search(String str) {
            this.a = str;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Search) && Intrinsics.b(this.a, ((Search) obj).a);
        }

        public final int hashCode() {
            String str = this.a;
            if (str == null) {
                return 0;
            }
            return str.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.t(new StringBuilder("Search(query="), this.a, ")");
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeString(this.a);
        }
    }

    @Metadata
    public static final class ViewAllExplanations extends GlobalNavReroute {
        public static final ViewAllExplanations a = new ViewAllExplanations();

        @NotNull
        public static final Parcelable.Creator<ViewAllExplanations> CREATOR = new i();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof ViewAllExplanations);
        }

        public final int hashCode() {
            return -738027286;
        }

        public final String toString() {
            return "ViewAllExplanations";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }

    @Metadata
    public static final class ViewAllSets extends GlobalNavReroute {
        public static final ViewAllSets a = new ViewAllSets();

        @NotNull
        public static final Parcelable.Creator<ViewAllSets> CREATOR = new j();

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        public final boolean equals(Object obj) {
            return this == obj || (obj instanceof ViewAllSets);
        }

        public final int hashCode() {
            return -1637424191;
        }

        public final String toString() {
            return "ViewAllSets";
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel dest, int i) {
            Intrinsics.checkNotNullParameter(dest, "dest");
            dest.writeInt(1);
        }
    }
}
