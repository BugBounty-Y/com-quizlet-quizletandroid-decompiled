package com.braze;

import androidx.compose.runtime.InterfaceC0773a0;
import com.braze.models.outgoing.BrazeProperties;
import java.math.BigDecimal;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1511q implements Function0 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    public /* synthetic */ C1511q(int i, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, InterfaceC0773a0 interfaceC0773a03, InterfaceC0773a0 interfaceC0773a04, kotlin.jvm.functions.d dVar) {
        this.b = i;
        this.c = dVar;
        this.d = interfaceC0773a0;
        this.e = interfaceC0773a02;
        this.f = interfaceC0773a03;
        this.g = interfaceC0773a04;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Braze braze = (Braze) this.f;
                return Braze.logPurchase$lambda$54((String) this.c, (String) this.d, (BigDecimal) this.e, this.b, braze, (BrazeProperties) this.g);
            default:
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.d;
                if (((androidx.compose.ui.text.input.A) interfaceC0773a0.getValue()).a.a.length() == 0) {
                    interfaceC0773a0.setValue(new androidx.compose.ui.text.input.A(6, 0L, String.valueOf(this.b)));
                }
                Integer numValueOf = Integer.valueOf(Integer.parseInt(((androidx.compose.ui.text.input.A) interfaceC0773a0.getValue()).a.a));
                Boolean bool = (Boolean) ((InterfaceC0773a0) this.e).getValue();
                bool.booleanValue();
                Boolean bool2 = (Boolean) ((InterfaceC0773a0) this.f).getValue();
                bool2.booleanValue();
                Boolean bool3 = (Boolean) ((InterfaceC0773a0) this.g).getValue();
                bool3.booleanValue();
                ((kotlin.jvm.functions.d) this.c).invoke(numValueOf, bool, bool2, bool3);
                return Unit.a;
        }
    }

    public /* synthetic */ C1511q(String str, String str2, BigDecimal bigDecimal, int i, Braze braze, BrazeProperties brazeProperties) {
        this.c = str;
        this.d = str2;
        this.e = bigDecimal;
        this.b = i;
        this.f = braze;
        this.g = brazeProperties;
    }
}
