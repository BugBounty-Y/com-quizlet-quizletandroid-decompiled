package com.quizlet.shared.usecase.studynotes;

import com.google.android.gms.internal.mlkit_vision_barcode.V4;
import com.quizlet.shared.models.api.notes.StudyNotesResponse;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public StudyNotesResponse j;
    public q k;
    public Map l;
    public Iterator m;
    public Map n;
    public String o;
    public String p;
    public /* synthetic */ Object q;
    public int r;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.r |= Integer.MIN_VALUE;
        return V4.k(null, null, this);
    }
}
