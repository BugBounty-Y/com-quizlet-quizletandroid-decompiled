package com.quizlet.shared.usecase.studynotes;

import com.quizlet.shared.models.api.notes.StudyNotesResponse;
import java.util.Collection;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public l j;
    public Collection k;
    public Iterator l;
    public StudyNotesResponse m;
    public String n;
    public String o;
    public String p;
    public String q;
    public Collection r;
    public boolean s;
    public long t;
    public /* synthetic */ Object u;
    public final /* synthetic */ l v;
    public int w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(l lVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.v = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.u = obj;
        this.w |= Integer.MIN_VALUE;
        return this.v.a(0, 0, false, this);
    }
}
