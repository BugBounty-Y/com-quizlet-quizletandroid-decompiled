package com.quizlet.search.composables;

import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes3.dex */
public final /* synthetic */ class M extends C4956o implements Function2 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ M(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                long jLongValue = ((Number) obj).longValue();
                long jLongValue2 = ((Number) obj2).longValue();
                com.quizlet.search.viewmodels.M m = (com.quizlet.search.viewmodels.M) this.receiver;
                m.getClass();
                kotlinx.coroutines.E.A(p0.j(m), null, null, new com.quizlet.search.viewmodels.L(m, jLongValue2, jLongValue, null), 3);
                return Unit.a;
            default:
                SerialDescriptor p0 = (SerialDescriptor) obj;
                int iIntValue = ((Number) obj2).intValue();
                Intrinsics.checkNotNullParameter(p0, "p0");
                kotlinx.serialization.json.internal.j jVar = (kotlinx.serialization.json.internal.j) this.receiver;
                jVar.getClass();
                boolean z = !p0.j(iIntValue) && p0.i(iIntValue).c();
                jVar.b = z;
                return Boolean.valueOf(z);
        }
    }
}
