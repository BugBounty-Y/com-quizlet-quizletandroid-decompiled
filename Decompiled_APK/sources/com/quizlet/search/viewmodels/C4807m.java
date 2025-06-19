package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.generated.enums.EnumC4466a1;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

/* renamed from: com.quizlet.search.viewmodels.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4807m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4807m(p pVar, boolean z, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = z;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4807m(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4807m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String str;
        s0 s0Var;
        Object value;
        String str2;
        EnumC4466a1 enumC4466a1;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        p pVar = this.k;
        if (i == 0) {
            Z.e(obj);
            y0 y0Var = pVar.m;
            if (y0Var != null) {
                y0Var.j(null);
            }
            this.j = 1;
            boolean z = this.l;
            String str3 = this.m;
            obj = z ? pVar.g.v(str3, this) : new com.quizlet.data.model.search.a(str3);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.data.model.search.a aVar2 = (com.quizlet.data.model.search.a) obj;
        pVar.getClass();
        int iOrdinal = aVar2.e.ordinal();
        String str4 = aVar2.b;
        String str5 = aVar2.a;
        if (iOrdinal == 0) {
            str = str4;
        } else {
            if (iOrdinal != 1 && iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            str = str5;
        }
        SearchEventLogger searchEventLogger = pVar.f;
        searchEventLogger.c();
        searchEventLogger.setQueryAndResetData(str);
        boolean z2 = aVar2.c;
        com.quizlet.data.model.search.b bVar = aVar2.e;
        if (z2) {
            int iOrdinal2 = bVar.ordinal();
            if (iOrdinal2 == 0) {
                enumC4466a1 = EnumC4466a1.MISSPELLINGS_QUERY_IS_SPELLCHECKED;
            } else if (iOrdinal2 == 1) {
                enumC4466a1 = EnumC4466a1.MISSPELLINGS_QUERY_IS_SUGGESTED;
            } else {
                if (iOrdinal2 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                enumC4466a1 = EnumC4466a1.MISSPELLINGS_QUERY_BELOW_THRESHOLD;
            }
            searchEventLogger.B(str5, str4, enumC4466a1);
        }
        do {
            s0Var = pVar.i;
            value = s0Var.getValue();
            int iOrdinal3 = bVar.ordinal();
            if (iOrdinal3 == 0) {
                str2 = str5;
            } else if (iOrdinal3 != 1) {
                if (iOrdinal3 != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                str2 = str5;
            } else {
                str2 = str4;
            }
        } while (!s0Var.k(value, new com.quizlet.search.data.f(str, str2, new com.quizlet.search.data.c(str5, str4, bVar))));
        return Unit.a;
    }
}
