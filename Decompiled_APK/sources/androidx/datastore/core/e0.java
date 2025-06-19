package androidx.datastore.core;

/* loaded from: classes.dex */
public final class e0 extends kotlin.coroutines.jvm.internal.c {
    public com.quizlet.data.repository.explanations.exercise.b j;
    public kotlinx.coroutines.sync.a k;
    public /* synthetic */ Object l;
    public final /* synthetic */ com.quizlet.data.repository.explanations.exercise.b m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e0(com.quizlet.data.repository.explanations.exercise.b bVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.h(this);
    }
}
