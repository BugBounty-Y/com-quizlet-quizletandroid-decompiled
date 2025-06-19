package com.quizlet.features.folders.viewmodel.usecases;

import com.google.android.gms.ads.internal.client.C1608n;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.c {
    public C1608n j;
    public c k;
    public ArrayList l;
    public ArrayList m;
    public int n;
    public boolean o;
    public /* synthetic */ Object p;
    public final /* synthetic */ C1608n q;
    public int r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(C1608n c1608n, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.q = c1608n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.p = obj;
        this.r |= Integer.MIN_VALUE;
        return this.q.u(null, this);
    }
}
