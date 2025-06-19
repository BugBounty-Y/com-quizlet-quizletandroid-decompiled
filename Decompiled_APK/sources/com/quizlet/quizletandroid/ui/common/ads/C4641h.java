package com.quizlet.quizletandroid.ui.common.ads;

import android.content.Context;
import android.util.DisplayMetrics;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4641h {
    public static final C4641h b = new C4641h(0);
    public final /* synthetic */ int a;

    public /* synthetic */ C4641h(int i) {
        this.a = i;
    }

    public Object a(Object obj) {
        switch (this.a) {
            case 2:
                C4640g input = (C4640g) obj;
                Intrinsics.checkNotNullParameter(input, "input");
                return new com.pubmatic.sdk.openwrap.eventhandler.dfp.b(input.a, input.b, input.c);
            case 3:
                Intrinsics.checkNotNullParameter((Unit) obj, "input");
                return new DisplayMetrics();
            default:
                Context input2 = (Context) obj;
                Intrinsics.checkNotNullParameter(input2, "input");
                return new com.pubmatic.sdk.openwrap.banner.c(input2);
        }
    }
}
