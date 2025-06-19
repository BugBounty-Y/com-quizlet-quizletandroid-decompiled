package com.quizlet.local.ormlite.database.dao;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function1;
import kotlin.text.x;

/* loaded from: classes3.dex */
public final class c implements Function1 {
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.data.repository.progress.c cVar = (com.quizlet.data.repository.progress.c) obj;
        long j = cVar.a;
        int iB = cVar.c.b();
        StringBuilder sbT = d0.t(j, "\n            (personId = ", "\n                AND containerId = ");
        sbT.append(cVar.b);
        sbT.append("\n                AND containerType = ");
        sbT.append(iB);
        sbT.append("\n            )\n            ");
        return x.c(sbT.toString());
    }
}
