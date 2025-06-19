package com.snowplowanalytics.core.tracker;

import android.util.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class f extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Pair b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ f(Pair pair, int i) {
        super(0);
        this.a = i;
        this.b = pair;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                Pair pair = this.b;
                if (pair != null) {
                    return (String) pair.first;
                }
                return null;
            case 1:
                Pair pair2 = this.b;
                if (pair2 != null) {
                    return (String) pair2.second;
                }
                return null;
            case 2:
                Pair pair3 = this.b;
                if (pair3 != null) {
                    return (String) pair3.first;
                }
                return null;
            default:
                Pair pair4 = this.b;
                if (pair4 != null) {
                    return (Integer) pair4.second;
                }
                return null;
        }
    }
}
