package com.quizlet.features.flashcards.engine;

import assistantMode.refactored.types.StudiableData;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public StudiableData j;
    public int k;
    public final /* synthetic */ h l;
    public final /* synthetic */ com.quizlet.features.infra.basestudy.data.models.dataproviders.a m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = hVar;
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:138:0x0497  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x05eb  */
    /* JADX WARN: Removed duplicated region for block: B:176:0x05f2  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0366  */
    /* JADX WARN: Type inference failed for: r2v12, types: [java.lang.Object, java.util.Set] */
    /* JADX WARN: Type inference failed for: r2v23, types: [java.lang.Object, java.util.Set] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r48) {
        /*
            Method dump skipped, instructions count: 1588
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.engine.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
