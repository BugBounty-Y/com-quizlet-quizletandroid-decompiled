package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final long a;
    public final String b;
    public final int c;
    public final int d;
    public final String e;
    public final String f;
    public final K0 g;

    public a(long j, String title, int i, int i2, String schoolName, String schoolLocation) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(schoolName, "schoolName");
        Intrinsics.checkNotNullParameter(schoolLocation, "schoolLocation");
        this.a = j;
        this.b = title;
        this.c = i;
        this.d = i2;
        this.e = schoolName;
        this.f = schoolLocation;
        this.g = K0.FREE;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.g;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && this.d == aVar.d && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f);
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
        return 4;
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.e(d0.b(this.d, d0.b(this.c, d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31), 31), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassCardUiModel(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", setsCount=");
        sb.append(this.c);
        sb.append(", membersCount=");
        sb.append(this.d);
        sb.append(", schoolName=");
        sb.append(this.e);
        sb.append(", schoolLocation=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }
}
