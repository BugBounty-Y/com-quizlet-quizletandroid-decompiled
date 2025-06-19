package com.quizlet.features.practicetest.detail.usecase;

import androidx.camera.camera2.internal.c0;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ String A;
    public Object j;
    public Object k;
    public Object l;
    public String m;
    public Object n;
    public Object o;
    public Object p;
    public PracticeTestConfigurationData q;
    public Boolean r;
    public int s;
    public int t;
    public boolean u;
    public boolean v;
    public boolean w;
    public int x;
    public /* synthetic */ Object y;
    public final /* synthetic */ c0 z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(c0 c0Var, String str, h hVar) {
        super(2, hVar);
        this.z = c0Var;
        this.A = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.z, this.A, hVar);
        dVar.y = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:48:0x01b3  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x01bf  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x01d9  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0212  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x0237  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x023a  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x024d  */
    /* JADX WARN: Removed duplicated region for block: B:79:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r10v9, types: [boolean] */
    /* JADX WARN: Type inference failed for: r11v7, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r7v8, types: [kotlinx.coroutines.H] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r33) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 604
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.detail.usecase.d.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
