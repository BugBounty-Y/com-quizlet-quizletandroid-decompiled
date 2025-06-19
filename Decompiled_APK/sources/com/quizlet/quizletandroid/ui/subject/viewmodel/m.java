package com.quizlet.quizletandroid.ui.subject.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_common.H3;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.generated.enums.H1;
import com.quizlet.generated.enums.I1;
import com.quizlet.generated.enums.K1;
import com.quizlet.quizletandroid.x;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class m extends com.quizlet.viewmodel.b {
    public final q c;
    public final x d;
    public final com.quizlet.data.interactor.achievements.f e;
    public final Y f;
    public final X g;
    public int h;
    public com.quizlet.features.subjects.model.b i;

    public m(m0 savedStateHandle, q subjectCategoryUseCase, x subjectDataProviderFactory, com.quizlet.data.interactor.achievements.f subjectLogger) {
        K1 k1;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(subjectCategoryUseCase, "subjectCategoryUseCase");
        Intrinsics.checkNotNullParameter(subjectDataProviderFactory, "subjectDataProviderFactory");
        Intrinsics.checkNotNullParameter(subjectLogger, "subjectLogger");
        this.c = subjectCategoryUseCase;
        this.d = subjectDataProviderFactory;
        this.e = subjectLogger;
        Y y = new Y();
        this.f = y;
        this.g = new X(1);
        y.j(f.a);
        H1 h1 = I1.Companion;
        String value = (String) savedStateHandle.a("subject_category_type");
        if (value == null) {
            throw new IllegalArgumentException("Subject category id must not be null");
        }
        h1.getClass();
        Intrinsics.checkNotNullParameter(value, "value");
        for (I1 i1 : I1.values()) {
            if (Intrinsics.b(i1.a(), value)) {
                String value2 = (String) savedStateHandle.a("subject_type");
                if (value2 != null) {
                    K1.Companion.getClass();
                    Intrinsics.checkNotNullParameter(value2, "value");
                    K1[] k1ArrValues = K1.values();
                    int length = k1ArrValues.length;
                    for (int i = 0; i < length; i++) {
                        k1 = k1ArrValues[i];
                        if (!Intrinsics.b(k1.a(), value2)) {
                        }
                    }
                    throw new NoSuchElementException("Array contains no element matching the predicate.");
                }
                k1 = null;
                E.A(p0.j(this), null, null, new j(this, i1, k1, null), 3);
                return;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    public static final Object B(m mVar, K1 k1, kotlin.coroutines.jvm.internal.i iVar) {
        Object next;
        com.quizlet.features.subjects.model.b bVar = mVar.i;
        if (bVar == null) {
            Intrinsics.m("subjectCategory");
            throw null;
        }
        List list = bVar.b;
        Iterator it2 = list.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((com.quizlet.features.subjects.model.a) next).a == k1) {
                break;
            }
        }
        com.quizlet.features.subjects.model.a aVar = (com.quizlet.features.subjects.model.a) next;
        if (aVar == null) {
            aVar = (com.quizlet.features.subjects.model.a) CollectionsKt.firstOrNull(list);
        }
        if (aVar != null) {
            com.quizlet.features.subjects.model.b bVar2 = mVar.i;
            if (bVar2 == null) {
                Intrinsics.m("subjectCategory");
                throw null;
            }
            List list2 = bVar2.b;
            ArrayList arrayList = new ArrayList(C.q(list2, 10));
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList.add(((com.quizlet.features.subjects.model.a) it3.next()).a);
            }
            kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i(arrayList);
            com.quizlet.features.subjects.model.b bVar3 = mVar.i;
            if (bVar3 == null) {
                Intrinsics.m("subjectCategory");
                throw null;
            }
            g gVar = new g(H3.a(bVar3.a), bVarI, bVarI.indexOf(aVar.a), AbstractC3409x1.i(K.a), true, false);
            mVar.f.j(gVar);
            Object objC = mVar.C(gVar, aVar, iVar);
            if (objC == kotlin.coroutines.intrinsics.a.a) {
                return objC;
            }
        }
        return Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object C(com.quizlet.quizletandroid.ui.subject.viewmodel.g r27, com.quizlet.features.subjects.model.a r28, kotlin.coroutines.jvm.internal.c r29) {
        /*
            Method dump skipped, instructions count: 361
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.subject.viewmodel.m.C(com.quizlet.quizletandroid.ui.subject.viewmodel.g, com.quizlet.features.subjects.model.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void D() {
        int i = this.h;
        com.quizlet.data.interactor.achievements.f fVar = this.e;
        fVar.getClass();
        EventLoggerExt.a((EventLogger) fVar.b, "leave_screen", new com.quizlet.features.setpage.logging.a(i, 1));
    }
}
