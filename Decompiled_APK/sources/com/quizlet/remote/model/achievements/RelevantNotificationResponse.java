package com.quizlet.remote.model.achievements;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RelevantNotificationResponse extends ApiResponse {
    public final NotificationData d;

    @m(generateAdapter = true)
    @Metadata
    public static final class NotificationData {
        public final String a;
        public final String b;
        public final String c;
        public final int d;
        public final String e;
        public final String f;
        public final BadgeImageUrlResponse g;
        public final String h;
        public final String i;

        public NotificationData(String achievementId, String type, String str, int i, String name, String description, BadgeImageUrlResponse imageUrl, String theme, String str2) {
            Intrinsics.checkNotNullParameter(achievementId, "achievementId");
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(description, "description");
            Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
            Intrinsics.checkNotNullParameter(theme, "theme");
            this.a = achievementId;
            this.b = type;
            this.c = str;
            this.d = i;
            this.e = name;
            this.f = description;
            this.g = imageUrl;
            this.h = theme;
            this.i = str2;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof NotificationData)) {
                return false;
            }
            NotificationData notificationData = (NotificationData) obj;
            return Intrinsics.b(this.a, notificationData.a) && Intrinsics.b(this.b, notificationData.b) && Intrinsics.b(this.c, notificationData.c) && this.d == notificationData.d && Intrinsics.b(this.e, notificationData.e) && Intrinsics.b(this.f, notificationData.f) && Intrinsics.b(this.g, notificationData.g) && Intrinsics.b(this.h, notificationData.h) && Intrinsics.b(this.i, notificationData.i);
        }

        public final int hashCode() {
            int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
            String str = this.c;
            int iE2 = d0.e((this.g.hashCode() + d0.e(d0.e(d0.b(this.d, (iE + (str == null ? 0 : str.hashCode())) * 31, 31), 31, this.e), 31, this.f)) * 31, 31, this.h);
            String str2 = this.i;
            return iE2 + (str2 != null ? str2.hashCode() : 0);
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("NotificationData(achievementId=");
            sb.append(this.a);
            sb.append(", type=");
            sb.append(this.b);
            sb.append(", winDate=");
            sb.append(this.c);
            sb.append(", goal=");
            sb.append(this.d);
            sb.append(", name=");
            sb.append(this.e);
            sb.append(", description=");
            sb.append(this.f);
            sb.append(", imageUrl=");
            sb.append(this.g);
            sb.append(", theme=");
            sb.append(this.h);
            sb.append(", goalTextAlignment=");
            return android.support.v4.media.session.a.t(sb, this.i, ")");
        }
    }

    public RelevantNotificationResponse(NotificationData notificationData) {
        this.d = notificationData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RelevantNotificationResponse) && Intrinsics.b(this.d, ((RelevantNotificationResponse) obj).d);
    }

    public final int hashCode() {
        NotificationData notificationData = this.d;
        if (notificationData == null) {
            return 0;
        }
        return notificationData.hashCode();
    }

    public final String toString() {
        return "RelevantNotificationResponse(data=" + this.d + ")";
    }
}
