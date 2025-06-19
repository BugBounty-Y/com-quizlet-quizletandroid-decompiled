package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import androidx.lifecycle.p0;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class t extends com.quizlet.viewmodel.b {
    public final androidx.work.impl.model.c c;
    public final com.quizlet.quizletandroid.managers.audio.h d;
    public y0 e;
    public final s0 f;
    public final s0 g;
    public final s0 h;
    public final s0 i;
    public final d0 j;
    public final Y k;
    public final d0 l;
    public final Y m;
    public boolean n;
    public StudiableMeteringData o;
    public StudiableMeteringData p;
    public ArrayList q;
    public int r;

    public t(androidx.work.impl.model.c userProperties, com.quizlet.quizletandroid.managers.audio.h audioManager) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(audioManager, "audioManager");
        this.c = userProperties;
        this.d = audioManager;
        K k = K.a;
        this.f = e0.c(new C4759a(k));
        this.g = e0.c(new I(k));
        this.h = e0.c(new H(k));
        this.i = e0.c(new C4760b(k));
        d0 d0VarB = e0.b(0, 0, null, 6);
        this.j = d0VarB;
        this.k = new Y(d0VarB);
        d0 d0VarB2 = e0.b(1, 0, null, 6);
        this.l = d0VarB2;
        this.m = new Y(d0VarB2);
    }

    public final void B(com.quizlet.uicommon.ui.common.util.d dVar, List list) {
        if (dVar instanceof com.quizlet.uicommon.ui.common.util.b) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new r(this, null), 3);
        } else if (Intrinsics.b(dVar, com.quizlet.uicommon.ui.common.util.c.a)) {
            kotlinx.coroutines.E.A(p0.j(this), null, null, new m(this, null), 3);
        } else {
            if (!(dVar instanceof com.quizlet.uicommon.ui.common.util.a)) {
                throw new NoWhenBranchMatchedException();
            }
            kotlinx.coroutines.E.A(p0.j(this), null, null, new n(this, list, null), 3);
        }
    }
}
