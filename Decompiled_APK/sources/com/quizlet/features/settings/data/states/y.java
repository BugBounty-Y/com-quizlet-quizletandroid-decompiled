package com.quizlet.features.settings.data.states;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y {
    public final String a;
    public final String b;
    public final boolean c;
    public final boolean d;
    public final com.quizlet.features.settings.data.models.f e;
    public final com.quizlet.features.settings.data.models.k f;
    public final com.quizlet.features.settings.data.models.e g;
    public final com.quizlet.themes.nighttheme.a h;
    public final boolean i;
    public final boolean j;
    public final String k;
    public final boolean l;
    public final boolean m;
    public final int n;
    public final boolean o;
    public final boolean p;
    public final boolean q;

    public y(String username, String email, boolean z, boolean z2, com.quizlet.features.settings.data.models.f reAuthType, com.quizlet.features.settings.data.models.k upgradeInfo, com.quizlet.features.settings.data.models.e offlineStorageInfo, com.quizlet.themes.nighttheme.a themeMode, boolean z3, boolean z4, String versionString, boolean z5, boolean z6) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
        Intrinsics.checkNotNullParameter(upgradeInfo, "upgradeInfo");
        Intrinsics.checkNotNullParameter(offlineStorageInfo, "offlineStorageInfo");
        Intrinsics.checkNotNullParameter(themeMode, "themeMode");
        Intrinsics.checkNotNullParameter(versionString, "versionString");
        this.a = username;
        this.b = email;
        this.c = z;
        this.d = z2;
        this.e = reAuthType;
        this.f = upgradeInfo;
        this.g = offlineStorageInfo;
        this.h = themeMode;
        this.i = z3;
        this.j = z4;
        this.k = versionString;
        this.l = z5;
        this.m = z6;
        this.n = z ? R.string.change_password_title : R.string.create_a_password;
        this.o = !Intrinsics.b(offlineStorageInfo, com.quizlet.features.settings.data.models.d.a);
        this.p = offlineStorageInfo instanceof com.quizlet.features.settings.data.models.c;
        this.q = offlineStorageInfo instanceof com.quizlet.features.settings.data.models.c ? ((com.quizlet.features.settings.data.models.c) offlineStorageInfo).a : false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r15v22, types: [com.quizlet.features.settings.data.models.e] */
    public static y a(y yVar, String str, String str2, boolean z, boolean z2, com.quizlet.features.settings.data.models.f fVar, com.quizlet.features.settings.data.models.k kVar, com.quizlet.features.settings.data.models.c cVar, com.quizlet.themes.nighttheme.a aVar, boolean z3, boolean z4, String str3, boolean z5, int i) {
        if ((i & 1) != 0) {
            str = yVar.a;
        }
        String username = str;
        String email = (i & 2) != 0 ? yVar.b : str2;
        boolean z6 = (i & 4) != 0 ? yVar.c : z;
        boolean z7 = (i & 8) != 0 ? yVar.d : z2;
        com.quizlet.features.settings.data.models.f reAuthType = (i & 16) != 0 ? yVar.e : fVar;
        com.quizlet.features.settings.data.models.k upgradeInfo = (i & 32) != 0 ? yVar.f : kVar;
        com.quizlet.features.settings.data.models.c offlineStorageInfo = (i & 64) != 0 ? yVar.g : cVar;
        com.quizlet.themes.nighttheme.a themeMode = (i & 128) != 0 ? yVar.h : aVar;
        boolean z8 = (i & 256) != 0 ? yVar.i : z3;
        boolean z9 = (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? yVar.j : z4;
        String versionString = (i & 1024) != 0 ? yVar.k : str3;
        boolean z10 = (i & 2048) != 0 ? yVar.l : false;
        boolean z11 = (i & 4096) != 0 ? yVar.m : z5;
        yVar.getClass();
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(reAuthType, "reAuthType");
        Intrinsics.checkNotNullParameter(upgradeInfo, "upgradeInfo");
        Intrinsics.checkNotNullParameter(offlineStorageInfo, "offlineStorageInfo");
        Intrinsics.checkNotNullParameter(themeMode, "themeMode");
        Intrinsics.checkNotNullParameter(versionString, "versionString");
        return new y(username, email, z6, z7, reAuthType, upgradeInfo, offlineStorageInfo, themeMode, z8, z9, versionString, z10, z11);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.a, yVar.a) && Intrinsics.b(this.b, yVar.b) && this.c == yVar.c && this.d == yVar.d && this.e == yVar.e && Intrinsics.b(this.f, yVar.f) && Intrinsics.b(this.g, yVar.g) && this.h == yVar.h && this.i == yVar.i && this.j == yVar.j && Intrinsics.b(this.k, yVar.k) && this.l == yVar.l && this.m == yVar.m;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.m) + d0.g(d0.e(d0.g(d0.g((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + d0.g(d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31)) * 31)) * 31)) * 31, 31, this.i), 31, this.j), 31, this.k), 31, this.l);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SettingsUiState(username=");
        sb.append(this.a);
        sb.append(", email=");
        sb.append(this.b);
        sb.append(", hasPassword=");
        sb.append(this.c);
        sb.append(", canChangeUsername=");
        sb.append(this.d);
        sb.append(", reAuthType=");
        sb.append(this.e);
        sb.append(", upgradeInfo=");
        sb.append(this.f);
        sb.append(", offlineStorageInfo=");
        sb.append(this.g);
        sb.append(", themeMode=");
        sb.append(this.h);
        sb.append(", arePushNotificationsEnabled=");
        sb.append(this.i);
        sb.append(", areSoundEffectsEnabled=");
        sb.append(this.j);
        sb.append(", versionString=");
        sb.append(this.k);
        sb.append(", isDebug=");
        sb.append(this.l);
        sb.append(", adsAndCookiesSectionEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.m);
    }
}
