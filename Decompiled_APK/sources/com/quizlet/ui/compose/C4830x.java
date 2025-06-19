package com.quizlet.ui.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3274u5;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.sdk.growthbook.evaluators.GBConditionEvaluator;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.B0;
import kotlinx.serialization.KSerializer;

/* renamed from: com.quizlet.ui.compose.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4830x implements Function2 {
    public final /* synthetic */ int a;

    public /* synthetic */ C4830x(int i) {
        this.a = 0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                AbstractC3274u5.b((InterfaceC0806l) obj, C0776c.H(1));
                return Unit.a;
            case 1:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$0((String) obj, (String) obj2));
            case 2:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$1(((Double) obj).doubleValue(), ((Double) obj2).doubleValue()));
            case 3:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$2((String) obj, (String) obj2));
            case 4:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$3(((Double) obj).doubleValue(), ((Double) obj2).doubleValue()));
            case 5:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$4((String) obj, (String) obj2));
            case 6:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$5(((Double) obj).doubleValue(), ((Double) obj2).doubleValue()));
            case 7:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$6((String) obj, (String) obj2));
            case 8:
                return Boolean.valueOf(GBConditionEvaluator.evalOperatorCondition$lambda$7(((Double) obj).doubleValue(), ((Double) obj2).doubleValue()));
            case 9:
                io.ktor.client.request.c it2 = (io.ktor.client.request.c) obj2;
                Intrinsics.checkNotNullParameter((io.ktor.client.plugins.P) obj, "<this>");
                Intrinsics.checkNotNullParameter(it2, "it");
                return Unit.a;
            case 10:
                io.ktor.client.plugins.N delayMillis = (io.ktor.client.plugins.N) obj;
                int iIntValue = ((Integer) obj2).intValue();
                Intrinsics.checkNotNullParameter(delayMillis, "$this$delayMillis");
                long jMin = Math.min((long) (Math.pow(2.0d, iIntValue - 1) * 1000), 60000L);
                kotlin.random.e.a.getClass();
                return Long.valueOf(kotlin.random.e.b.h() + jMin);
            case 11:
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj2, "<unused var>");
                return Boolean.TRUE;
            case 12:
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj2, "<unused var>");
                return Boolean.TRUE;
            case 13:
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj2, "<unused var>");
                return Boolean.TRUE;
            case 14:
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj2, "<unused var>");
                return Boolean.TRUE;
            case 15:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                return bool;
            case 16:
                return ((CoroutineContext) obj).plus((CoroutineContext.Element) obj2);
            case 17:
                return ((CoroutineContext) obj).plus((CoroutineContext.Element) obj2);
            case 18:
                return Integer.valueOf(((Integer) obj).intValue() + 1);
            case 19:
                CoroutineContext.Element element = (CoroutineContext.Element) obj2;
                if (!(element instanceof B0)) {
                    return obj;
                }
                Integer num = obj instanceof Integer ? (Integer) obj : null;
                int iIntValue2 = num != null ? num.intValue() : 1;
                return iIntValue2 == 0 ? element : Integer.valueOf(iIntValue2 + 1);
            case 20:
                B0 b0 = (B0) obj;
                CoroutineContext.Element element2 = (CoroutineContext.Element) obj2;
                if (b0 != null) {
                    return b0;
                }
                if (element2 instanceof B0) {
                    return (B0) element2;
                }
                return null;
            case 21:
                return (kotlinx.coroutines.internal.v) obj;
            case EventType.WINDOW_STATE /* 22 */:
                kotlin.reflect.c clazz = (kotlin.reflect.c) obj;
                List types = (List) obj2;
                Intrinsics.checkNotNullParameter(clazz, "clazz");
                Intrinsics.checkNotNullParameter(types, "types");
                ArrayList arrayListH = P1.h(kotlinx.serialization.modules.f.a, types, true);
                Intrinsics.d(arrayListH);
                return P1.c(clazz, arrayListH, new com.braze.managers.U(types, 9));
            default:
                kotlin.reflect.c clazz2 = (kotlin.reflect.c) obj;
                List types2 = (List) obj2;
                Intrinsics.checkNotNullParameter(clazz2, "clazz");
                Intrinsics.checkNotNullParameter(types2, "types");
                ArrayList arrayListH2 = P1.h(kotlinx.serialization.modules.f.a, types2, true);
                Intrinsics.d(arrayListH2);
                KSerializer kSerializerC = P1.c(clazz2, arrayListH2, new com.braze.managers.U(types2, 10));
                if (kSerializerC != null) {
                    return R1.e(kSerializerC);
                }
                return null;
        }
    }

    public /* synthetic */ C4830x(int i, byte b) {
        this.a = i;
    }
}
