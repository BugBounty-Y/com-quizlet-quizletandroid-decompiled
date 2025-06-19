package com.quizlet.features.setpage.screenstates;

import androidx.compose.animation.d0;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.setpage.viewmodel.C4437k;
import com.quizlet.utm.a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends A {
    public final long a;
    public final String b;
    public final String c;
    public final a.C0023a d;
    public final EventLogger e;
    public final C4437k f;
    public final com.quizlet.features.infra.basestudy.data.models.shareset.a g;
    public final int h;

    public z(long j, String str, String title, a.C0023a utmInfo, EventLogger eventLogger, C4437k shareMsgGenerator, com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus, int i) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(utmInfo, "utmInfo");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(shareMsgGenerator, "shareMsgGenerator");
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        this.a = j;
        this.b = str;
        this.c = title;
        this.d = utmInfo;
        this.e = eventLogger;
        this.f = shareMsgGenerator;
        this.g = shareStatus;
        this.h = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return this.a == zVar.a && Intrinsics.b(this.b, zVar.b) && this.c.equals(zVar.c) && this.d.equals(zVar.d) && Intrinsics.b(this.e, zVar.e) && this.f.equals(zVar.f) && this.g == zVar.g && this.h == zVar.h;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return Integer.hashCode(this.h) + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c)) * 31)) * 961)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Share(setId=");
        sb.append(this.a);
        sb.append(", webUrl=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", utmInfo=");
        sb.append(this.d);
        sb.append(", eventLogger=");
        sb.append(this.e);
        sb.append(", studyModeUrlFragment=null, shareMsgGenerator=");
        sb.append(this.f);
        sb.append(", shareStatus=");
        sb.append(this.g);
        sb.append(", setAccessType=");
        return android.support.v4.media.session.a.r(sb, this.h, ")");
    }
}
