package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final Integer e;
    public final int f;
    public final int g;
    public final K0 h;

    public h(long j, String userImage, String username, boolean z, Integer num, int i, int i2) {
        Intrinsics.checkNotNullParameter(userImage, "userImage");
        Intrinsics.checkNotNullParameter(username, "username");
        this.a = j;
        this.b = userImage;
        this.c = username;
        this.d = z;
        this.e = num;
        this.f = i;
        this.g = i2;
        this.h = K0.FREE;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.h;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c) && this.d == hVar.d && Intrinsics.b(this.e, hVar.e) && this.f == hVar.f && this.g == hVar.g;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final long getItemId() {
        return this.a;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return Long.valueOf(this.a);
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final int getModelType() {
        return 2;
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
        Integer num = this.e;
        return Integer.hashCode(this.g) + d0.b(this.f, (iG + (num == null ? 0 : num.hashCode())) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UserCardUiModel(id=");
        sb.append(this.a);
        sb.append(", userImage=");
        sb.append(this.b);
        sb.append(", username=");
        sb.append(this.c);
        sb.append(", isVerified=");
        sb.append(this.d);
        sb.append(", userBadge=");
        sb.append(this.e);
        sb.append(", studySets=");
        sb.append(this.f);
        sb.append(", classes=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}
