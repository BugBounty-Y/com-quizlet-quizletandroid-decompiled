package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.StudySet;
import com.quizlet.generated.enums.P;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public InterfaceC4176w0 j;
    public boolean k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ s n;
    public final /* synthetic */ long o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(s sVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = sVar;
        this.o = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.n, this.o, hVar);
        nVar.m = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((StudySet) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        boolean zD;
        StudySet studySet;
        boolean z;
        InterfaceC4176w0 interfaceC4176w0;
        StudySet studySet2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        long j = this.o;
        s sVar = this.n;
        if (i == 0) {
            Z.e(obj);
            StudySet studySet3 = (StudySet) this.m;
            zD = sVar.c.d(j);
            P p = P.TEST_SUBMISSION;
            this.m = studySet3;
            this.k = zD;
            this.l = 1;
            Object objB = s.b(sVar, j, p, this);
            if (objB != aVar) {
                studySet = studySet3;
                obj = objB;
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            z = this.k;
            interfaceC4176w0 = this.j;
            studySet2 = (StudySet) this.m;
            Z.e(obj);
            return new com.quizlet.features.infra.basestudy.data.models.u(studySet2, z, interfaceC4176w0, (InterfaceC4176w0) obj);
        }
        zD = this.k;
        studySet = (StudySet) this.m;
        Z.e(obj);
        InterfaceC4176w0 interfaceC4176w02 = (InterfaceC4176w0) obj;
        P p2 = P.LEARN_CHECKPOINT;
        this.m = studySet;
        this.j = interfaceC4176w02;
        this.k = zD;
        this.l = 2;
        Object objB2 = s.b(sVar, j, p2, this);
        if (objB2 != aVar) {
            z = zD;
            interfaceC4176w0 = interfaceC4176w02;
            obj = objB2;
            studySet2 = studySet;
            return new com.quizlet.features.infra.basestudy.data.models.u(studySet2, z, interfaceC4176w0, (InterfaceC4176w0) obj);
        }
        return aVar;
    }
}
