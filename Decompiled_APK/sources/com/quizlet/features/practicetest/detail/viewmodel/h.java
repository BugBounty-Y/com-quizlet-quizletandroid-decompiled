package com.quizlet.features.practicetest.detail.viewmodel;

import com.quizlet.data.exceptions.practicetests.PracticeTestCreationException;
import com.quizlet.data.exceptions.practicetests.PracticeTestNoInternetException;
import com.quizlet.data.exceptions.practicetests.PracticeTestPaywallException;
import com.quizlet.data.exceptions.practicetests.PracticeTestPrivateException;
import com.quizlet.data.exceptions.practicetests.PracticeTestUnsupportedException;
import com.quizlet.features.practicetest.detail.data.G;
import com.quizlet.features.practicetest.detail.data.r;
import com.quizlet.features.practicetest.detail.data.u;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A;
import kotlinx.coroutines.C5041z;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.a implements A {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    /* JADX WARN: Illegal instructions before constructor call */
    public h(i iVar, int i) {
        this.a = i;
        switch (i) {
            case 1:
                C5041z c5041z = C5041z.a;
                this.b = iVar;
                super(c5041z);
                break;
            default:
                C5041z c5041z2 = C5041z.a;
                this.b = iVar;
                super(c5041z2);
                break;
        }
    }

    @Override // kotlinx.coroutines.A
    public final void handleException(CoroutineContext coroutineContext, Throwable th) {
        Object value;
        Object value2;
        Object value3;
        Object value4;
        Object value5;
        switch (this.a) {
            case 0:
                boolean z = th instanceof PracticeTestNoInternetException;
                i iVar = this.b;
                if (!z) {
                    iVar.k.h(new r(false));
                    break;
                } else {
                    iVar.k.h(new r(true));
                    break;
                }
            default:
                boolean z2 = th instanceof PracticeTestPrivateException;
                i iVar2 = this.b;
                if (!z2) {
                    if (!(th instanceof PracticeTestNoInternetException)) {
                        if (!(th instanceof PracticeTestUnsupportedException)) {
                            if (!(th instanceof PracticeTestPaywallException)) {
                                if (!(th instanceof PracticeTestCreationException)) {
                                    s0 s0Var = iVar2.l;
                                    do {
                                        value = s0Var.getValue();
                                    } while (!s0Var.k(value, new G(new com.quizlet.features.practicetest.common.data.c(new g(iVar2, 3)))));
                                    timber.log.c.a.p(th);
                                    break;
                                } else {
                                    s0 s0Var2 = iVar2.l;
                                    do {
                                        value2 = s0Var2.getValue();
                                    } while (!s0Var2.k(value2, new G(new com.quizlet.features.practicetest.common.data.b(new g(iVar2, 2)))));
                                    timber.log.c.a.p(th);
                                    break;
                                }
                            } else {
                                d0 d0Var = iVar2.k;
                                com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.x;
                                Intrinsics.checkNotNullParameter("create_practice_test", "upgradeSource");
                                Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
                                d0Var.h(new u());
                                break;
                            }
                        } else {
                            s0 s0Var3 = iVar2.l;
                            do {
                                value3 = s0Var3.getValue();
                            } while (!s0Var3.k(value3, new G(new com.quizlet.features.practicetest.common.data.f(new g(iVar2, 1)))));
                        }
                    } else {
                        s0 s0Var4 = iVar2.l;
                        do {
                            value4 = s0Var4.getValue();
                        } while (!s0Var4.k(value4, new G(new com.quizlet.features.practicetest.common.data.d(new g(iVar2, 0)))));
                    }
                } else {
                    s0 s0Var5 = iVar2.l;
                    do {
                        value5 = s0Var5.getValue();
                    } while (!s0Var5.k(value5, new G(com.quizlet.features.practicetest.common.data.e.a)));
                }
        }
    }
}
