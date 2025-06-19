package com.braze.triggers.managers;

import com.braze.ui.UserJavascriptInterfaceBase;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;

    public /* synthetic */ j(int i, String str, String str2) {
        this.a = i;
        this.b = str;
        this.c = str2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.a(this.b, this.c);
            case 1:
                return b.b(this.b, this.c);
            case 2:
                return b.c(this.b, this.c);
            case 3:
                return UserJavascriptInterfaceBase.setCustomAttribute$lambda$31(this.b, this.c);
            default:
                return UserJavascriptInterfaceBase.setCustomAttribute$lambda$32(this.b, this.c);
        }
    }
}
