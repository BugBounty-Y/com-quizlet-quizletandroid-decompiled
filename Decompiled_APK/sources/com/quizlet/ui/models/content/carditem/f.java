package com.quizlet.ui.models.content.carditem;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.K0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements com.quizlet.ui.models.search.a, com.quizlet.ui.models.impressions.a {
    public final long a;
    public final String b;
    public final int c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final String h;
    public final String i;
    public final int j;
    public final boolean k;
    public final K0 l;
    public final com.quizlet.ui.models.search.e m;
    public final int n;
    public final K0 o;

    public f(long j, String setName, int i, boolean z, boolean z2, boolean z3, boolean z4, String username, String str, int i2, boolean z5, K0 k0, com.quizlet.ui.models.search.e eVar, int i3) {
        boolean z6 = (i3 & 32) != 0 ? false : z3;
        boolean z7 = (i3 & 64) != 0 ? false : z4;
        String userImage = (i3 & 256) != 0 ? "" : str;
        int i4 = (i3 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? 0 : i2;
        boolean z8 = (i3 & 1024) == 0 ? z5 : false;
        K0 setPurchasableType = (i3 & 2048) != 0 ? K0.FREE : k0;
        com.quizlet.ui.models.search.e eVar2 = (i3 & 4096) != 0 ? null : eVar;
        Intrinsics.checkNotNullParameter(setName, "setName");
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(userImage, "userImage");
        Intrinsics.checkNotNullParameter(setPurchasableType, "setPurchasableType");
        this.a = j;
        this.b = setName;
        this.c = i;
        this.d = z;
        this.e = z2;
        this.f = z6;
        this.g = z7;
        this.h = username;
        this.i = userImage;
        this.j = i4;
        this.k = z8;
        this.l = setPurchasableType;
        this.m = eVar2;
        this.n = 1;
        this.o = setPurchasableType;
    }

    @Override // com.quizlet.ui.models.impressions.a
    public final K0 a() {
        return this.o;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && this.c == fVar.c && this.d == fVar.d && this.e == fVar.e && this.f == fVar.f && this.g == fVar.g && Intrinsics.b(this.h, fVar.h) && Intrinsics.b(this.i, fVar.i) && this.j == fVar.j && this.k == fVar.k && this.l == fVar.l && Intrinsics.b(this.m, fVar.m);
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
        return this.n;
    }

    public final int hashCode() {
        int iHashCode = (this.l.hashCode() + d0.g(d0.b(this.j, d0.e(d0.e(d0.g(d0.g(d0.g(d0.g(d0.b(this.c, d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31), 31, this.k)) * 31;
        com.quizlet.ui.models.search.e eVar = this.m;
        return iHashCode + (eVar == null ? 0 : eVar.hashCode());
    }

    public final String toString() {
        return "StudySetCardUiModel(id=" + this.a + ", setName=" + this.b + ", terms=" + this.c + ", hasImages=" + this.d + ", hasDiagrams=" + this.e + ", isLocked=" + this.f + ", isDraft=" + this.g + ", username=" + this.h + ", userImage=" + this.i + ", userBadge=" + this.j + ", userIsVerified=" + this.k + ", setPurchasableType=" + this.l + ", socialSignals=" + this.m + ")";
    }
}
