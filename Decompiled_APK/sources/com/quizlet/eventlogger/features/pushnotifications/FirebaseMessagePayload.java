package com.quizlet.eventlogger.features.pushnotifications;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4495k0;
import com.quizlet.generated.enums.S1;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class FirebaseMessagePayload implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<FirebaseMessagePayload> CREATOR = new Creator();

    @NotNull
    private final String channel;
    private final EnumC4495k0 destination;
    private final Long folderId;

    @NotNull
    private final String messageId;
    private final Long setId;
    private final S1 type;
    private final long userId;

    @Metadata
    public static final class Creator implements Parcelable.Creator<FirebaseMessagePayload> {
        @Override // android.os.Parcelable.Creator
        public final FirebaseMessagePayload createFromParcel(Parcel parcel) {
            Intrinsics.checkNotNullParameter(parcel, "parcel");
            return new FirebaseMessagePayload(parcel.readString(), parcel.readLong(), parcel.readInt() == 0 ? null : S1.valueOf(parcel.readString()), parcel.readString(), parcel.readInt() == 0 ? null : EnumC4495k0.valueOf(parcel.readString()), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() != 0 ? Long.valueOf(parcel.readLong()) : null);
        }

        @Override // android.os.Parcelable.Creator
        public final FirebaseMessagePayload[] newArray(int i) {
            return new FirebaseMessagePayload[i];
        }
    }

    public FirebaseMessagePayload(@NotNull String messageId, long j, S1 s1, @NotNull String channel, EnumC4495k0 enumC4495k0, Long l, Long l2) {
        Intrinsics.checkNotNullParameter(messageId, "messageId");
        Intrinsics.checkNotNullParameter(channel, "channel");
        this.messageId = messageId;
        this.userId = j;
        this.type = s1;
        this.channel = channel;
        this.destination = enumC4495k0;
        this.setId = l;
        this.folderId = l2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FirebaseMessagePayload)) {
            return false;
        }
        FirebaseMessagePayload firebaseMessagePayload = (FirebaseMessagePayload) obj;
        return Intrinsics.b(this.messageId, firebaseMessagePayload.messageId) && this.userId == firebaseMessagePayload.userId && this.type == firebaseMessagePayload.type && Intrinsics.b(this.channel, firebaseMessagePayload.channel) && this.destination == firebaseMessagePayload.destination && Intrinsics.b(this.setId, firebaseMessagePayload.setId) && Intrinsics.b(this.folderId, firebaseMessagePayload.folderId);
    }

    @NotNull
    public final String getChannel() {
        return this.channel;
    }

    public final EnumC4495k0 getDestination() {
        return this.destination;
    }

    public final Long getFolderId() {
        return this.folderId;
    }

    @NotNull
    public final String getMessageId() {
        return this.messageId;
    }

    public final Long getSetId() {
        return this.setId;
    }

    public final S1 getType() {
        return this.type;
    }

    public final long getUserId() {
        return this.userId;
    }

    public final int hashCode() {
        int iD = d0.d(this.messageId.hashCode() * 31, 31, this.userId);
        S1 s1 = this.type;
        int iE = d0.e((iD + (s1 == null ? 0 : s1.hashCode())) * 31, 31, this.channel);
        EnumC4495k0 enumC4495k0 = this.destination;
        int iHashCode = (iE + (enumC4495k0 == null ? 0 : enumC4495k0.hashCode())) * 31;
        Long l = this.setId;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.folderId;
        return iHashCode2 + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "FirebaseMessagePayload(messageId=" + this.messageId + ", userId=" + this.userId + ", type=" + this.type + ", channel=" + this.channel + ", destination=" + this.destination + ", setId=" + this.setId + ", folderId=" + this.folderId + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.messageId);
        dest.writeLong(this.userId);
        S1 s1 = this.type;
        if (s1 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(s1.name());
        }
        dest.writeString(this.channel);
        EnumC4495k0 enumC4495k0 = this.destination;
        if (enumC4495k0 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeString(enumC4495k0.name());
        }
        Long l = this.setId;
        if (l == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l.longValue());
        }
        Long l2 = this.folderId;
        if (l2 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l2.longValue());
        }
    }

    public /* synthetic */ FirebaseMessagePayload(String str, long j, S1 s1, String str2, EnumC4495k0 enumC4495k0, Long l, Long l2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, j, s1, str2, (i & 16) != 0 ? null : enumC4495k0, (i & 32) != 0 ? null : l, (i & 64) != 0 ? null : l2);
    }
}
