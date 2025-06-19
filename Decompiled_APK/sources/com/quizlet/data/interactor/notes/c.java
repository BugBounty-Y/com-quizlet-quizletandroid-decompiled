package com.quizlet.data.interactor.notes;

import com.quizlet.shared.models.notes.NewStudyNotesInfo;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public NewStudyNotesInfo j;
    public int k;
    public final /* synthetic */ androidx.work.impl.background.greedy.d l;
    public final /* synthetic */ List m;
    public final /* synthetic */ boolean n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(androidx.work.impl.background.greedy.d dVar, List list, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = dVar;
        this.m = list;
        this.n = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:68:0x00f9, code lost:
    
        if (r15 == r0) goto L69;
     */
    /* JADX WARN: Removed duplicated region for block: B:133:0x021b  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x009d  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r15) throws com.quizlet.data.exceptions.notes.NotesException {
        /*
            Method dump skipped, instructions count: 612
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.notes.c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
