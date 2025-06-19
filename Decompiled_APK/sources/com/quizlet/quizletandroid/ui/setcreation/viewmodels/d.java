package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    public /* synthetic */ d(e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Boolean shouldShow = (Boolean) obj;
                Intrinsics.checkNotNullParameter(shouldShow, "shouldShow");
                if (shouldShow.booleanValue()) {
                    e eVar = this.b;
                    eVar.n.j(Unit.a);
                    assistantMode.refactored.a.p(eVar.e.a, "check_in_switch_prompt_tooltip", true);
                    break;
                }
                break;
            case 1:
                Boolean isUserUnderAged = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isUserUnderAged, "isUserUnderAged");
                e eVar2 = this.b;
                eVar2.i.j(Boolean.valueOf((isUserUnderAged.booleanValue() || Intrinsics.b((Boolean) eVar2.j.d(), Boolean.TRUE) || ((com.quizlet.qutils.android.a) eVar2.k.d()) == com.quizlet.qutils.android.a.b) ? false : true));
                break;
            default:
                Boolean isEnabled = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isEnabled, "isEnabled");
                this.b.m.j(isEnabled.booleanValue() ? f.a : f.b);
                break;
        }
    }
}
