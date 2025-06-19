package com.braze;

import com.braze.support.BrazeFileUtils;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class P implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ int c;

    public /* synthetic */ P(int i, String str) {
        this.a = 2;
        this.c = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.incrementCustomUserAttribute$lambda$58(this.b, this.c);
            case 1:
                return com.braze.models.outgoing.event.a.b(this.b, this.c);
            default:
                return BrazeFileUtils.downloadFileToPath$lambda$8(this.c, this.b);
        }
    }

    public /* synthetic */ P(String str, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = i;
    }
}
