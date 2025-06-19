package com.quizlet.features.settings.composables.updatepassword;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.settings.viewmodels.q;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;
    public final /* synthetic */ InterfaceC0773a0 c;
    public final /* synthetic */ InterfaceC0773a0 d;
    public final /* synthetic */ InterfaceC0773a0 e;

    public /* synthetic */ a(q qVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, InterfaceC0773a0 interfaceC0773a03, int i) {
        this.a = i;
        this.b = qVar;
        this.c = interfaceC0773a0;
        this.d = interfaceC0773a02;
        this.e = interfaceC0773a03;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                String str = (String) this.c.getValue();
                this.b.t((String) this.d.getValue(), (String) this.e.getValue(), str);
                break;
            case 1:
                String str2 = (String) this.c.getValue();
                this.b.m((String) this.d.getValue(), (String) this.e.getValue(), str2);
                break;
            case 2:
                String str3 = (String) this.c.getValue();
                this.b.t((String) this.d.getValue(), (String) this.e.getValue(), str3);
                break;
            default:
                String str4 = (String) this.c.getValue();
                this.b.m((String) this.d.getValue(), (String) this.e.getValue(), str4);
                break;
        }
        return Unit.a;
    }
}
