package com.quizlet.features.notes.upload.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.notes.NotesException;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import java.util.Locale;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public NotesToValueInfo j;
    public int k;
    public final /* synthetic */ e l;
    public final /* synthetic */ String m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = eVar;
        this.m = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws NotesException {
        Object value;
        NotesToValueInfo notesToValueInfo;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        String str = this.m;
        e eVar = this.l;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var = eVar.t;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, new com.quizlet.features.notes.upload.states.f(eVar.l)));
            boolean z = !eVar.D();
            Integer num = new Integer(str.length());
            String lowerCase = eVar.v.name().toLowerCase(Locale.ROOT);
            Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
            int i2 = com.quizlet.features.notes.logging.f.d;
            eVar.q.b(z, num, K.a, lowerCase);
            boolean zD = eVar.D();
            this.k = 1;
            obj = eVar.r.a(str, zD, eVar.u, this);
            if (obj != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            notesToValueInfo = this.j;
            Z.e(obj);
            eVar.F(notesToValueInfo, (AddMaterialFolderData) obj);
            return Unit.a;
        }
        Z.e(obj);
        NotesToValueInfo notesToValueInfo2 = (NotesToValueInfo) obj;
        com.quizlet.features.notes.logging.f fVar = eVar.q;
        String str2 = notesToValueInfo2.a;
        Integer num2 = new Integer(str.length());
        String lowerCase2 = eVar.v.name().toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
        int i3 = com.quizlet.features.notes.logging.f.d;
        fVar.c(str2, num2, K.a, lowerCase2);
        eVar.B(notesToValueInfo2);
        this.j = notesToValueInfo2;
        this.k = 2;
        Object objJ = eVar.J(notesToValueInfo2.a, this);
        if (objJ != aVar) {
            notesToValueInfo = notesToValueInfo2;
            obj = objJ;
            eVar.F(notesToValueInfo, (AddMaterialFolderData) obj);
            return Unit.a;
        }
        return aVar;
    }
}
