package com.quizlet.features.onboarding.ell;

import androidx.datastore.core.InterfaceC1076h;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.measurement.internal.J;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ J k;
    public final /* synthetic */ List l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(J j, List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            J j = this.k;
            com.lyft.android.scissors.b bVar = (com.lyft.android.scissors.b) j.e;
            List list = this.l;
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                arrayList.add(((m) it2.next()).name());
            }
            Set setA0 = CollectionsKt.A0(arrayList);
            this.j = 1;
            String name = String.format("user_onboarding_ell_exams_%s", Arrays.copyOf(new Object[]{new Long(j.b)}, 1));
            Intrinsics.checkNotNullExpressionValue(name, "format(...)");
            Intrinsics.checkNotNullParameter(name, "name");
            Object objD = S6.d((InterfaceC1076h) bVar.b, new com.quizlet.local.datastore.preferences.Z(new androidx.datastore.preferences.core.f(name), setA0, null), this);
            if (objD != kotlin.coroutines.intrinsics.a.a) {
                objD = Unit.a;
            }
            if (objD == obj2) {
                return obj2;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
