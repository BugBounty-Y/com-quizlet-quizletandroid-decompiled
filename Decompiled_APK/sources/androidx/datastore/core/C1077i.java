package androidx.datastore.core;

/* renamed from: androidx.datastore.core.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1077i extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.explanations.exercise.b j;
    public /* synthetic */ Object k;
    public final /* synthetic */ com.quizlet.data.repository.explanations.exercise.b l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1077i(com.quizlet.data.repository.explanations.exercise.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.b(this);
    }
}
