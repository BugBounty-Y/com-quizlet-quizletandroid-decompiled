package com.quizlet.security.challenge.ui;

import androidx.compose.ui.platform.C0958o;
import androidx.lifecycle.p0;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import com.quizlet.quizletandroid.ui.learnpaywall.f;
import com.quizlet.quizletandroid.ui.learnpaywall.g;
import com.quizlet.quizletandroid.ui.learnpaywall.k;
import com.quizlet.security.challenge.viewmodel.c;
import com.quizlet.security.challenge.viewmodel.d;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoDialogModalFragment;
import com.quizlet.upgrade.ui.fragment.FreeTrialConfirmationFragment;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class b extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((d) this.receiver).h.h(com.quizlet.security.challenge.viewmodel.b.a);
                break;
            case 1:
                d dVar = (d) this.receiver;
                dVar.B();
                Boolean bool = Boolean.TRUE;
                s0 s0Var = dVar.i;
                s0Var.getClass();
                s0Var.m(null, bool);
                dVar.d.b(com.quizlet.security.challenge.eventlogging.d.b);
                E.A(p0.j(dVar), null, null, new c(dVar, null), 3);
                break;
            case 2:
                ((InfoDialogModalFragment) this.receiver).H(false, false);
                break;
            case 3:
                k kVar = (k) ((com.quizlet.upgrade.paywall.viewmodel.a) this.receiver);
                kVar.getClass();
                C0958o c0958o = new C0958o(3, kVar.b, StudyModeMeteringEventLogger.class, "logPaywallPrimaryAction", "logPaywallPrimaryAction(JLjava/lang/String;Lcom/quizlet/studiablemodels/StudiableMeteringData;)V", 0, 3);
                Long l = kVar.h;
                String str = kVar.i;
                StudiableMeteringData studiableMeteringData = kVar.j;
                if (l != null && str != null && studiableMeteringData != null) {
                    c0958o.invoke(l, str, studiableMeteringData);
                }
                com.quizlet.quizletandroid.ui.learnpaywall.b bVar = kVar.g;
                String str2 = bVar != null ? bVar.a : null;
                if (str2 == null) {
                    str2 = "";
                }
                E.A(p0.j(kVar), null, null, new f(kVar, new com.quizlet.upgrade.paywall.data.b(str2, bVar != null ? bVar.b : com.quizlet.features.infra.models.upgrade.a.e), null), 3);
                break;
            case 4:
                k kVar2 = (k) ((com.quizlet.upgrade.paywall.viewmodel.a) this.receiver);
                kVar2.getClass();
                E.A(p0.j(kVar2), null, null, new g(kVar2, null), 3);
                break;
            case 5:
                ((k) ((com.quizlet.upgrade.paywall.viewmodel.a) this.receiver)).B();
                break;
            default:
                ((FreeTrialConfirmationFragment) this.receiver).G();
                break;
        }
        return Unit.a;
    }
}
