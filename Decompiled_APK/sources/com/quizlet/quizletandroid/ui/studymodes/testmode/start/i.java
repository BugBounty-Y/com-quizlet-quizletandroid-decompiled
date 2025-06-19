package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final TestStudyModeConfig a;
    public final boolean b;
    public final int c;
    public final ArrayList d;
    public final String e;

    public i(TestStudyModeConfig settings, boolean z, int i, ArrayList availableSides, String setTitle) {
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(availableSides, "availableSides");
        Intrinsics.checkNotNullParameter(setTitle, "setTitle");
        this.a = settings;
        this.b = z;
        this.c = i;
        this.d = availableSides;
        this.e = setTitle;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b == iVar.b && this.c == iVar.c && Intrinsics.b(this.d, iVar.d) && this.e.equals(iVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.h(this.d, d0.b(this.c, d0.g(this.a.hashCode() * 31, 31, this.b), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StartScreenData(settings=");
        sb.append(this.a);
        sb.append(", isSmartGradingEnabled=");
        sb.append(this.b);
        sb.append(", termCount=");
        sb.append(this.c);
        sb.append(", availableSides=");
        sb.append(this.d);
        sb.append(", setTitle=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
