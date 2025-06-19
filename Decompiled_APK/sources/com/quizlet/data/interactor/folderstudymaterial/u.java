package com.quizlet.data.interactor.folderstudymaterial;

import com.quizlet.generated.enums.y1;
import java.util.List;

/* loaded from: classes2.dex */
public final class u extends kotlin.coroutines.jvm.internal.c {
    public String j;
    public y1 k;
    public List l;
    public List m;
    public /* synthetic */ Object n;
    public final /* synthetic */ com.onetrust.otpublishers.headless.UI.fragment.q o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(com.onetrust.otpublishers.headless.UI.fragment.q qVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        Object objR = this.o.r(null, null, null, null, this);
        return objR == kotlin.coroutines.intrinsics.a.a ? objR : new kotlin.r(objR);
    }
}
