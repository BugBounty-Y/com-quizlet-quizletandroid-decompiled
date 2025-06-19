package com.quizlet.features.setpage.termlist;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.features.setpage.termlist.data.h;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ TermListComposeFragment b;

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        TermListComposeFragment termListComposeFragment = this.b;
        switch (this.a) {
            case 0:
                long jLongValue = ((Long) obj).longValue();
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                String str = TermListComposeFragment.m;
                termListComposeFragment.U().B(new h(jLongValue, zBooleanValue));
                break;
            default:
                ((Integer) obj2).getClass();
                String str2 = TermListComposeFragment.m;
                termListComposeFragment.T((InterfaceC0806l) obj, C0776c.H(1));
                break;
        }
        return Unit.a;
    }
}
