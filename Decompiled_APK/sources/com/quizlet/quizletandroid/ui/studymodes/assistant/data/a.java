package com.quizlet.quizletandroid.ui.studymodes.assistant.data;

import com.quizlet.data.repository.progress.b;
import com.quizlet.learn.data.C4537b;
import com.quizlet.learn.data.P;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ b j;
    public final /* synthetic */ C4537b k;
    public final /* synthetic */ List l;
    public final /* synthetic */ List m;
    public final /* synthetic */ P n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, C4537b c4537b, List list, List list2, P p, h hVar) {
        super(2, hVar);
        this.j = bVar;
        this.k = c4537b;
        this.l = list;
        this.m = list2;
        this.n = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x026b  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x027a  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x0291  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0294  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x02d8  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x02f3  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0313  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0326  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0359  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x038e  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r35) throws org.koin.core.error.DefinitionOverrideException, org.koin.core.error.KoinAppAlreadyStartedException {
        /*
            Method dump skipped, instructions count: 932
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.studymodes.assistant.data.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
