package com.quizlet.upgrade.ui.fragment;

import androidx.lifecycle.C0;
import androidx.lifecycle.InterfaceC1261w;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class m extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ m(int i, Object obj, Object obj2) {
        super(0);
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, kotlin.k] */
    /* JADX WARN: Type inference failed for: r0v11, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                C0 c0 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w = c0 instanceof InterfaceC1261w ? (InterfaceC1261w) c0 : null;
                if (interfaceC1261w == null || (r0 = interfaceC1261w.getDefaultViewModelProviderFactory()) == null) {
                    break;
                }
                break;
            case 1:
                C0 c02 = (C0) this.b.getValue();
                InterfaceC1261w interfaceC1261w2 = c02 instanceof InterfaceC1261w ? (InterfaceC1261w) c02 : null;
                if (interfaceC1261w2 == null || (r0 = interfaceC1261w2.getDefaultViewModelProviderFactory()) == null) {
                    break;
                }
                break;
            case 2:
                org.koin.core.instance.c cVar = (org.koin.core.instance.c) this.c;
                if (cVar.b == null) {
                    cVar.b = cVar.a((com.quizlet.data.repository.set.f) this.b);
                }
                break;
            default:
                ((org.wordpress.aztec.formatting.n) this.c).u().append((CharSequence) this.b);
                break;
        }
        return Unit.a;
    }
}
