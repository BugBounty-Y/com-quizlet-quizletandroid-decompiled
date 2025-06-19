package com.quizlet.login.signup.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.login.signup.data.r;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, long j, h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        s0 s0Var;
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.k;
        if (i == 0) {
            Z.e(obj);
            Object obj2 = gVar.f.b;
            long j = this.l;
            LocalDate localDate = Instant.ofEpochMilli(j).atZone(ZoneId.systemDefault()).toLocalDate();
            LocalDate localDateNow = LocalDate.now();
            Intrinsics.checkNotNullExpressionValue(localDateNow, "now(...)");
            boolean zIsBefore = localDate.isBefore(localDateNow.minusYears(21L));
            do {
                s0Var = gVar.g;
                value = s0Var.getValue();
            } while (!s0Var.k(value, r.a((r) value, false, zIsBefore, null, null, null, 59)));
            this.j = 1;
            obj = gVar.e.p(j, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.login.common.interactors.data.d dVar = (com.quizlet.login.common.interactors.data.d) obj;
        s0 s0Var2 = gVar.g;
        do {
            value2 = s0Var2.getValue();
        } while (!s0Var2.k(value2, r.a((r) value2, false, false, null, null, dVar, 31)));
        return Unit.a;
    }
}
