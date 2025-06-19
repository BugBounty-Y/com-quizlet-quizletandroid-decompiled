package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class U1 {
    public final long a;
    public final double b;
    public final ArrayList c;

    public U1(long j, double d, ArrayList lineage) {
        Intrinsics.checkNotNullParameter(lineage, "lineage");
        this.a = j;
        this.b = d;
        this.c = lineage;
    }

    public final LinkedHashMap a() {
        ArrayList arrayList = this.c;
        int iA = kotlin.collections.U.a(kotlin.collections.C.q(arrayList, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            X1 x1 = (X1) it2.next();
            linkedHashMap.put(android.support.v4.media.session.a.f(x1.a, "ct_level"), x1.b);
        }
        return linkedHashMap;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U1)) {
            return false;
        }
        U1 u1 = (U1) obj;
        return this.a == u1.a && Double.compare(this.b, u1.b) == 0 && this.c.equals(u1.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.a(this.b, Long.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudySetClassification(id=");
        sb.append(this.a);
        sb.append(", score=");
        sb.append(this.b);
        sb.append(", lineage=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
