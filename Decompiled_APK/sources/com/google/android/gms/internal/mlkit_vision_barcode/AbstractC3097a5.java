package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.content.res.Resources;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.shared.models.api.metering.MeteredEvent;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.a5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3097a5 {
    public static final Resources a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.j(AndroidCompositionLocals_androidKt.a);
        return ((Context) c0814p.j(AndroidCompositionLocals_androidKt.b)).getResources();
    }

    public static final com.quizlet.shared.enums.h b(com.quizlet.generated.enums.P p) {
        Intrinsics.checkNotNullParameter(p, "<this>");
        switch (com.quizlet.studiablemodels.d.a[p.ordinal()]) {
            case 1:
                return com.quizlet.shared.enums.h.b;
            case 2:
                return com.quizlet.shared.enums.h.c;
            case 3:
                return com.quizlet.shared.enums.h.d;
            case 4:
                return com.quizlet.shared.enums.h.c;
            case 5:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 6:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 7:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 8:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 9:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 10:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 11:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            case 12:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
            default:
                throw new IllegalStateException("Could not find equivalent MeteredEventType " + p);
        }
    }

    public static final ArrayList c(List list) {
        Intrinsics.checkNotNullParameter(list, "<this>");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            com.quizlet.ui.models.content.listitem.o oVar = (com.quizlet.ui.models.content.listitem.o) it2.next();
            Intrinsics.checkNotNullParameter(oVar, "<this>");
            arrayList.add(new com.quizlet.data.model.I1(oVar.d(), oVar.b()));
        }
        return arrayList;
    }

    public static final StudiableMeteringData d(InterfaceC4176w0 interfaceC4176w0) {
        Intrinsics.checkNotNullParameter(interfaceC4176w0, "<this>");
        if (interfaceC4176w0 instanceof C4179x0) {
            C4179x0 c4179x0 = (C4179x0) interfaceC4176w0;
            return new StudiableMeteringData(b(c4179x0.c), Integer.valueOf(c4179x0.a), Integer.valueOf(c4179x0.b));
        }
        if (interfaceC4176w0 instanceof com.quizlet.data.model.o2) {
            return new StudiableMeteringData(b(((com.quizlet.data.model.o2) interfaceC4176w0).a), null, null);
        }
        throw new NoWhenBranchMatchedException();
    }

    public static final StudiableMeteringData e(Map map) {
        Intrinsics.checkNotNullParameter(map, "<this>");
        Map.Entry entry = (Map.Entry) CollectionsKt.M(map.entrySet());
        if (entry == null) {
            return null;
        }
        com.quizlet.shared.enums.h hVar = (com.quizlet.shared.enums.h) entry.getKey();
        MeteredEvent meteredEvent = (MeteredEvent) entry.getValue();
        return new StudiableMeteringData(hVar, Integer.valueOf(meteredEvent.a), Integer.valueOf(meteredEvent.b));
    }
}
