package com.quizlet.features.universaluploadflow.data;

import androidx.compose.animation.d0;
import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class G implements K {
    public final m2 a;
    public final C4458g b;
    public final Integer c;

    public G(m2 source, C4458g guidelinesConfig, Integer num) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(guidelinesConfig, "guidelinesConfig");
        this.a = source;
        this.b = guidelinesConfig;
        this.c = num;
    }

    @Override // com.quizlet.features.universaluploadflow.data.K
    public final boolean a() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return this.a == g.a && this.b.equals(g.b) && Intrinsics.b(this.c, g.c);
    }

    public final int hashCode() {
        int iG = d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, false);
        Integer num = this.c;
        return iG + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(source=");
        sb.append(this.a);
        sb.append(", guidelinesConfig=");
        sb.append(this.b);
        sb.append(", showFlashcardsUploadButton=false, remainingUploadsUsage=");
        return assistantMode.refactored.a.l(sb, this.c, ")");
    }
}
