package com.quizlet.security.challenge.core;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.local.datastore.preferences.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.studysetwithcreatorinclass.g k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.k;
        if (i == 0) {
            Z.e(obj);
            J j = (J) gVar.c;
            this.j = 1;
            obj = j.a("CF_CLEARANCE_KEY", this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        String str = (String) obj;
        if (str != null) {
            gVar.q(str);
        }
        return Unit.a;
    }
}
