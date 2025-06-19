package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.data.model.StudySet;
import com.quizlet.generated.enums.A1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4686b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public StudySet j;
    public int k;
    public final /* synthetic */ s l;
    public final /* synthetic */ A1 m;
    public final /* synthetic */ long n;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C4686b(s sVar, A1 a1, long j, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = sVar;
        this.m = a1;
        this.n = j;
        this.o = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4686b(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4686b) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x00a1, code lost:
    
        if (r13 != r0) goto L38;
     */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0097 A[PHI: r1
  0x0097: PHI (r1v3 com.quizlet.data.model.StudySet) = 
  (r1v2 com.quizlet.data.model.StudySet)
  (r1v2 com.quizlet.data.model.StudySet)
  (r1v2 com.quizlet.data.model.StudySet)
  (r1v4 com.quizlet.data.model.StudySet)
 binds: [B:33:0x0094, B:27:0x0079, B:21:0x005e, B:12:0x0029] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r13v20, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r13) throws java.lang.Throwable {
        /*
            r12 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r12.k
            com.quizlet.generated.enums.A1 r2 = r12.m
            r3 = 5
            r4 = 4
            r5 = 3
            r6 = 0
            r7 = 2
            r8 = 1
            long r9 = r12.n
            com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s r11 = r12.l
            if (r1 == 0) goto L34
            if (r1 == r8) goto L30
            if (r1 == r7) goto L29
            if (r1 == r5) goto L29
            if (r1 == r4) goto L29
            if (r1 != r3) goto L21
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto La4
        L21:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r0)
            throw r13
        L29:
            com.quizlet.data.model.StudySet r1 = r12.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L97
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L45
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger r13 = r11.h
            r13.l(r2)
            r12.k = r8
            java.lang.Object r13 = com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s.c(r11, r9, r12)
            if (r13 != r0) goto L45
            goto La3
        L45:
            r1 = r13
            com.quizlet.data.model.StudySet r1 = (com.quizlet.data.model.StudySet) r1
            int[] r13 = com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.AbstractC4685a.a
            int r2 = r2.ordinal()
            r13 = r13[r2]
            if (r13 == r8) goto L7c
            if (r13 == r7) goto L61
            com.quizlet.remote.model.notes.e r13 = r11.b
            r12.j = r1
            r12.k = r4
            java.lang.Object r13 = r13.p(r9, r12)
            if (r13 != r0) goto L97
            goto La3
        L61:
            com.quizlet.remote.model.notes.e r13 = r11.b
            r12.j = r1
            r12.k = r5
            com.quizlet.features.setpage.studymodes.data.e r2 = new com.quizlet.features.setpage.studymodes.data.e
            r2.<init>(r13, r9, r6)
            java.lang.Object r13 = r13.c
            kotlinx.coroutines.y r13 = (kotlinx.coroutines.AbstractC5040y) r13
            java.lang.Object r13 = kotlinx.coroutines.E.J(r13, r2, r12)
            if (r13 != r0) goto L77
            goto L79
        L77:
            kotlin.Unit r13 = kotlin.Unit.a
        L79:
            if (r13 != r0) goto L97
            goto La3
        L7c:
            com.quizlet.remote.model.notes.e r13 = r11.b
            r12.j = r1
            r12.k = r7
            com.quizlet.features.setpage.studymodes.data.i r2 = new com.quizlet.features.setpage.studymodes.data.i
            r2.<init>(r13, r9, r6)
            java.lang.Object r13 = r13.c
            kotlinx.coroutines.y r13 = (kotlinx.coroutines.AbstractC5040y) r13
            java.lang.Object r13 = kotlinx.coroutines.E.J(r13, r2, r12)
            if (r13 != r0) goto L92
            goto L94
        L92:
            kotlin.Unit r13 = kotlin.Unit.a
        L94:
            if (r13 != r0) goto L97
            goto La3
        L97:
            r12.j = r6
            r12.k = r3
            kotlin.coroutines.jvm.internal.i r13 = r12.o
            java.lang.Object r13 = r13.invoke(r1, r12)
            if (r13 != r0) goto La4
        La3:
            return r0
        La4:
            com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger r0 = r11.h
            r0.m()
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.C4686b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
