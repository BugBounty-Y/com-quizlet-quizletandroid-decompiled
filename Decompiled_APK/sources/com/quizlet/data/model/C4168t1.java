package com.quizlet.data.model;

import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.t1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4168t1 {
    public final List a;

    public /* synthetic */ C4168t1(List list) {
        this.a = list;
    }

    public static final List a(List list, Function1 function1) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (((Boolean) function1.invoke(((N1) obj).a())).booleanValue()) {
                arrayList.add(obj);
            }
        }
        List listP0 = CollectionsKt.p0(arrayList, 10);
        if (listP0.isEmpty()) {
            return null;
        }
        return listP0;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C4168t1) {
            return Intrinsics.b(this.a, ((C4168t1) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("RecommendedStudyMaterials(studyMaterials="), this.a);
    }
}
