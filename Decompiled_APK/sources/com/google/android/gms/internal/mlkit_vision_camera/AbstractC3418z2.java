package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.work.EnumC1420a;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.z2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3418z2 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.Collection] */
    public static final void a(org.koin.core.definition.d dVar, C4950i clazz) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        org.koin.core.instance.b bVar = dVar.b;
        org.koin.core.definition.b bVar2 = bVar.a;
        ArrayList arrayListD0 = CollectionsKt.d0(bVar2.f, clazz);
        Intrinsics.checkNotNullParameter(arrayListD0, "<set-?>");
        bVar2.f = arrayListD0;
        org.koin.core.definition.b bVar3 = bVar.a;
        dVar.a.c(AbstractC3402v2.b(clazz, bVar3.c, bVar3.a), bVar);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, java.util.Collection] */
    public static final void b(org.koin.core.definition.d dVar, kotlin.reflect.c[] elements) {
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(elements, "classes");
        org.koin.core.instance.b bVar = dVar.b;
        org.koin.core.definition.b bVar2 = bVar.a;
        ?? r3 = bVar2.f;
        Intrinsics.checkNotNullParameter(r3, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        ArrayList arrayList = new ArrayList(r3.size() + elements.length);
        arrayList.addAll(r3);
        kotlin.collections.G.v(arrayList, elements);
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        bVar2.f = arrayList;
        for (kotlin.reflect.c cVar : elements) {
            org.koin.core.definition.b bVar3 = bVar.a;
            dVar.a.c(AbstractC3402v2.b(cVar, bVar3.c, bVar3.a), bVar);
        }
    }

    public static long c(boolean z, int i, EnumC1420a backoffPolicy, long j, long j2, int i2, boolean z2, long j3, long j4, long j5, long j6) {
        Intrinsics.checkNotNullParameter(backoffPolicy, "backoffPolicy");
        if (j6 != Long.MAX_VALUE && z2) {
            if (i2 != 0) {
                long j7 = j2 + 900000;
                if (j6 < j7) {
                    return j7;
                }
            }
            return j6;
        }
        if (z) {
            long jScalb = backoffPolicy == EnumC1420a.b ? j * i : (long) Math.scalb(j, i - 1);
            if (jScalb > 18000000) {
                jScalb = 18000000;
            }
            return j2 + jScalb;
        }
        if (z2) {
            long j8 = i2 == 0 ? j2 + j3 : j2 + j5;
            return (j4 == j5 || i2 != 0) ? j8 : (j5 - j4) + j8;
        }
        if (j2 == -1) {
            return Long.MAX_VALUE;
        }
        return j2 + j3;
    }
}
