package com.google.firebase.sessions;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.jvm.functions.Function0;

/* loaded from: classes2.dex */
public final class r extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ r(Context context, int i) {
        super(0);
        this.a = i;
        this.b = context;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return P6.d(this.b, E.b);
            default:
                return P6.d(this.b, E.a);
        }
    }
}
