package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class J1 {
    public final String a;
    public final String b;
    public final ArrayList c;

    public J1(String startDateFormatted, String endDateFormatted, ArrayList daysData) {
        Intrinsics.checkNotNullParameter(startDateFormatted, "startDateFormatted");
        Intrinsics.checkNotNullParameter(endDateFormatted, "endDateFormatted");
        Intrinsics.checkNotNullParameter(daysData, "daysData");
        this.a = startDateFormatted;
        this.b = endDateFormatted;
        this.c = daysData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof J1)) {
            return false;
        }
        J1 j1 = (J1) obj;
        return Intrinsics.b(this.a, j1.a) && Intrinsics.b(this.b, j1.b) && this.c.equals(j1.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StreakCalendarData(startDateFormatted=");
        sb.append(this.a);
        sb.append(", endDateFormatted=");
        sb.append(this.b);
        sb.append(", daysData=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
