package com.quizlet.shared.usecase.studynotes;

import com.quizlet.shared.models.api.notes.CreateStudyNotesResponse;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.c {
    public n j;
    public CreateStudyNotesResponse k;
    public Object l;
    public Iterator m;
    public Map n;
    public String o;
    public long p;
    public int q;
    public /* synthetic */ Object r;
    public final /* synthetic */ n s;
    public int t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(n nVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.s = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.r = obj;
        this.t |= Integer.MIN_VALUE;
        return this.s.a(null, this);
    }
}
