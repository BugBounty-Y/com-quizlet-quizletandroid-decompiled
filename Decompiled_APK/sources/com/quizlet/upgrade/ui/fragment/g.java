package com.quizlet.upgrade.ui.fragment;

import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class g extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ UpgradeFragment b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(UpgradeFragment upgradeFragment, kotlin.k kVar, int i) {
        super(0);
        this.a = i;
        this.b = upgradeFragment;
        this.c = kVar;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v10, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                C0 c0 = (C0) this.c.getValue();
                InterfaceC1261w interfaceC1261w = c0 instanceof InterfaceC1261w ? (InterfaceC1261w) c0 : null;
                if (interfaceC1261w == null || (r0 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) {
                    break;
                }
                break;
            default:
                C0 c02 = (C0) this.c.getValue();
                InterfaceC1261w interfaceC1261w2 = c02 instanceof InterfaceC1261w ? (InterfaceC1261w) c02 : null;
                if (interfaceC1261w2 == null || (r0 = interfaceC1261w2.getDefaultViewModelProviderFactory()) == null) {
                    break;
                }
                break;
        }
        return this.b.getDefaultViewModelProviderFactory();
    }
}
