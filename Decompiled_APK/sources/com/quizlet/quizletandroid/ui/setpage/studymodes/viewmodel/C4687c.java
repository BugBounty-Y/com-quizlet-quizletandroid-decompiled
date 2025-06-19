package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.data.model.StudySet;
import java.util.List;

/* renamed from: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4687c extends kotlin.coroutines.jvm.internal.c {
    public StudySet j;
    public List k;
    public boolean l;
    public /* synthetic */ Object m;
    public final /* synthetic */ s n;
    public int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4687c(s sVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.n = sVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.m = obj;
        this.o |= Integer.MIN_VALUE;
        return s.a(this.n, null, false, null, this);
    }
}
