package androidx.datastore.core;

import java.io.Serializable;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.datastore.core.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1080l extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public Object j;
    public Serializable k;
    public Object l;
    public Object m;
    public Iterator n;
    public int o;
    public int p;
    public final /* synthetic */ P q;
    public final /* synthetic */ com.quizlet.data.repository.explanations.exercise.b r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1080l(P p, com.quizlet.data.repository.explanations.exercise.b bVar, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.q = p;
        this.r = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C1080l(this.q, this.r, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C1080l) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00da  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00e9  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0104  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) {
        /*
            Method dump skipped, instructions count: 281
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.C1080l.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
