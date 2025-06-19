package com.quizlet.data.interactor.studiablemetadata;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.shared.usecase.studiableMetadata.c;
import com.quizlet.shared.usecase.studiableMetadata.d;
import com.quizlet.shared.usecase.studiableMetadata.g;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ b k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, long j, h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        b bVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                g gVar = bVar.a;
                long j = this.l;
                List list = b.c;
                this.j = 1;
                obj = E.m(new c(list, (d) gVar, j, null), this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (Map) obj;
        } catch (Exception e) {
            bVar.b.j("An exception occurred while fetching remote StudiableMetadata", e);
            return V.c();
        }
    }
}
