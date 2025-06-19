package com.google.android.gms.internal.mlkit_vision_camera;

import android.content.Context;
import android.content.Intent;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0976x0;
import androidx.navigation.C1291m;
import androidx.navigation.compose.C1277j;
import androidx.navigation.compose.C1278k;
import androidx.navigation.compose.C1279l;
import androidx.navigation.compose.C1280m;
import androidx.work.C1444s;
import com.google.android.gms.internal.mlkit_vision_barcode.M4;
import com.google.android.gms.internal.mlkit_vision_barcode.W5;
import com.quizlet.features.practicetest.PracticeTestActivity;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Set;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;

/* loaded from: classes2.dex */
public abstract class L1 {
    public static final void a(androidx.navigation.compose.s sVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.navigation.compose.s sVar2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(294589392);
        if ((((c0814p.h(sVar) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
            sVar2 = sVar;
        } else {
            androidx.compose.runtime.saveable.f fVarB = M4.b(c0814p);
            InterfaceC0773a0 interfaceC0773a0M = C0776c.m(sVar.b().e, c0814p);
            List list = (List) interfaceC0773a0M.getValue();
            boolean zBooleanValue = ((Boolean) c0814p.j(AbstractC0976x0.a)).booleanValue();
            boolean zF = c0814p.f(list);
            Object objI = c0814p.I();
            Object obj = C0804k.a;
            Object obj2 = objI;
            if (zF || objI == obj) {
                androidx.compose.runtime.snapshots.q qVar = new androidx.compose.runtime.snapshots.q();
                ArrayList arrayList = new ArrayList();
                for (Object obj3 : list) {
                    if (zBooleanValue ? true : ((C1291m) obj3).h.j.d.a(androidx.lifecycle.B.d)) {
                        arrayList.add(obj3);
                    }
                }
                qVar.addAll(arrayList);
                c0814p.i0(qVar);
                obj2 = qVar;
            }
            androidx.compose.runtime.snapshots.q qVar2 = (androidx.compose.runtime.snapshots.q) obj2;
            b(qVar2, (List) interfaceC0773a0M.getValue(), c0814p, 0);
            InterfaceC0773a0 interfaceC0773a0M2 = C0776c.m(sVar.b().f, c0814p);
            Object objI2 = c0814p.I();
            if (objI2 == obj) {
                objI2 = new androidx.compose.runtime.snapshots.q();
                c0814p.i0(objI2);
            }
            androidx.compose.runtime.snapshots.q qVar3 = (androidx.compose.runtime.snapshots.q) objI2;
            c0814p.X(-367418626);
            ListIterator listIterator = qVar2.listIterator();
            while (true) {
                androidx.compose.runtime.snapshots.w wVar = (androidx.compose.runtime.snapshots.w) listIterator;
                if (!wVar.hasNext()) {
                    break;
                }
                C1291m c1291m = (C1291m) wVar.next();
                androidx.navigation.B b = c1291m.b;
                Intrinsics.e(b, "null cannot be cast to non-null type androidx.navigation.compose.DialogNavigator.Destination");
                androidx.navigation.compose.r rVar = (androidx.navigation.compose.r) b;
                boolean zH = c0814p.h(sVar) | c0814p.h(c1291m);
                Object objI3 = c0814p.I();
                if (zH || objI3 == obj) {
                    objI3 = new C1277j(0, sVar, c1291m);
                    c0814p.i0(objI3);
                }
                Function0 function0 = (Function0) objI3;
                androidx.compose.runtime.snapshots.q qVar4 = qVar3;
                androidx.navigation.compose.s sVar3 = sVar;
                W5.a(function0, rVar.f, androidx.compose.runtime.internal.e.e(1129586364, new androidx.navigation.compose.p(c1291m, sVar3, fVarB, qVar4, rVar, 0), c0814p), c0814p, 384);
                sVar = sVar3;
                qVar3 = qVar4;
            }
            sVar2 = sVar;
            androidx.compose.runtime.snapshots.q qVar5 = qVar3;
            c0814p.p(false);
            Set set = (Set) interfaceC0773a0M2.getValue();
            boolean zF2 = c0814p.f(interfaceC0773a0M2) | c0814p.h(sVar2);
            Object objI4 = c0814p.I();
            if (zF2 || objI4 == obj) {
                objI4 = new androidx.navigation.compose.q(interfaceC0773a0M2, sVar2, qVar5, null);
                c0814p.i0(objI4);
            }
            C0776c.g(set, qVar5, (Function2) objI4, c0814p);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(sVar2, i, 0);
        }
    }

    public static final void b(androidx.compose.runtime.snapshots.q qVar, List list, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1537894851);
        if ((((c0814p.h(qVar) ? 4 : 2) | i | (c0814p.h(list) ? 32 : 16)) & 19) == 18 && c0814p.x()) {
            c0814p.Q();
        } else {
            boolean zBooleanValue = ((Boolean) c0814p.j(AbstractC0976x0.a)).booleanValue();
            Iterator it2 = list.iterator();
            while (it2.hasNext()) {
                C1291m c1291m = (C1291m) it2.next();
                androidx.lifecycle.L l = c1291m.h.j;
                boolean zG = c0814p.g(zBooleanValue) | c0814p.h(qVar) | c0814p.h(c1291m);
                Object objI = c0814p.I();
                if (zG || objI == C0804k.a) {
                    objI = new C1279l(c1291m, zBooleanValue, qVar, 0);
                    c0814p.i0(objI);
                }
                C0776c.d(l, (Function1) objI, c0814p);
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1280m(qVar, list, i, 0);
        }
    }

    public static Intent c(Context context, String questionBankUuid) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(questionBankUuid, "questionBankUuid");
        Intent intent = new Intent(context, (Class<?>) PracticeTestActivity.class);
        intent.putExtra("questionBankUuid", questionBankUuid);
        return intent;
    }

    public static Intent d(Context context, String uuid, com.quizlet.data.model.U0 origin) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(origin, "origin");
        Intent intent = new Intent(context, (Class<?>) PracticeTestActivity.class);
        if (com.quizlet.features.practicetest.a.a[origin.ordinal()] == 1) {
            intent.putExtra("practiceTestId", uuid);
        } else {
            intent.putExtra("questionBankUuid", uuid);
        }
        intent.putExtra("navigationRoute", "takingTest");
        intent.putExtra("navigationOrigin", origin.a);
        return intent;
    }

    public static final io.reactivex.rxjava3.internal.operators.flowable.b e(CoroutineContext coroutineContext, Function2 function2) {
        if (coroutineContext.get(C5023i0.a) == null) {
            return new io.reactivex.rxjava3.internal.operators.flowable.b(new C1444s(coroutineContext, function2, 1), 3);
        }
        throw new IllegalArgumentException(("Single context cannot contain job in it.Its lifecycle should be managed via Disposable handle. Had " + coroutineContext).toString());
    }
}
