package com.braze;

import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1482h implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Braze c;
    public final /* synthetic */ String d;

    public /* synthetic */ C1482h(String str, Braze braze, String str2) {
        this.a = 2;
        this.b = str;
        this.d = str2;
        this.c = braze;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.addSerializedCardJsonToStorage$lambda$180(this.b, this.c, this.d);
            case 1:
                return Braze.changeUser$lambda$138(this.b, this.c, this.d);
            default:
                return Braze.logPushStoryPageClicked$lambda$71(this.b, this.d, this.c);
        }
    }

    public /* synthetic */ C1482h(String str, Braze braze, String str2, int i) {
        this.a = i;
        this.b = str;
        this.c = braze;
        this.d = str2;
    }
}
