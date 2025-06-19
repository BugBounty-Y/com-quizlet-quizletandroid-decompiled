package com.braze.support;

import java.io.File;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ File b;

    public /* synthetic */ o(File file, int i) {
        this.a = i;
        this.b = file;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeFileUtils.deleteFileOrDirectory$lambda$0(this.b);
            case 1:
                return BrazeImageUtils.getLocalBitmap$lambda$10(this.b);
            default:
                return com.braze.triggers.managers.a.b(this.b);
        }
    }
}
