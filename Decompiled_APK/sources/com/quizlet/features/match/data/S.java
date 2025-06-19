package com.quizlet.features.match.data;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.match.settings.MatchSettingsData;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class S {
    public final MatchSettingsData a;
    public final int b;
    public final ArrayList c;
    public final boolean d;
    public final StudyEventLogData e;
    public final ArrayList f;

    public S(MatchSettingsData currentSettings, int i, ArrayList availableStudiableCardSideLabels, boolean z, StudyEventLogData studyEventLogData) {
        Intrinsics.checkNotNullParameter(currentSettings, "currentSettings");
        Intrinsics.checkNotNullParameter(availableStudiableCardSideLabels, "availableStudiableCardSideLabels");
        Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
        this.a = currentSettings;
        this.b = i;
        this.c = availableStudiableCardSideLabels;
        this.d = z;
        this.e = studyEventLogData;
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(availableStudiableCardSideLabels, 10));
        Iterator it2 = availableStudiableCardSideLabels.iterator();
        while (it2.hasNext()) {
            arrayList.add(Integer.valueOf(AbstractC3106b5.g((assistantMode.enums.m) it2.next()).a()));
        }
        this.f = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S)) {
            return false;
        }
        S s = (S) obj;
        return this.a.equals(s.a) && this.b == s.b && Intrinsics.b(this.c, s.c) && this.d == s.d && this.e.equals(s.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.h(this.c, androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31), 31, this.d);
    }

    public final String toString() {
        return "MatchStartSettingsData(currentSettings=" + this.a + ", selectedItemsCount=" + this.b + ", availableStudiableCardSideLabels=" + this.c + ", isMatchRunning=" + this.d + ", studyEventLogData=" + this.e + ")";
    }
}
