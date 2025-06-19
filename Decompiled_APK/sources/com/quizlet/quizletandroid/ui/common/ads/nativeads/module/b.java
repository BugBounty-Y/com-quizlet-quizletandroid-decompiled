package com.quizlet.quizletandroid.ui.common.ads.nativeads.module;

import com.google.android.gms.ads.k;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.v;

/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.functions.e {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.e
    public final Object k(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                String setWebUrl = (String) obj2;
                boolean zBooleanValue2 = ((Boolean) obj3).booleanValue();
                Intrinsics.checkNotNullParameter(setWebUrl, "setWebUrl");
                return new a(setWebUrl, zBooleanValue, zBooleanValue2);
            default:
                k p0 = (k) obj;
                Map p1 = (Map) obj2;
                Map p2 = (Map) obj3;
                Intrinsics.checkNotNullParameter(p0, "p0");
                Intrinsics.checkNotNullParameter(p1, "p1");
                Intrinsics.checkNotNullParameter(p2, "p2");
                return new v(p0, p1, p2);
        }
    }
}
