package com.braze.requests.framework;

import com.google.android.gms.internal.mlkit_vision_camera.L1;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    public /* synthetic */ k(int i, int i2, long j, Object obj) {
        this.a = i2;
        this.d = obj;
        this.b = j;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.a((h) this.d, this.b, this.c);
            default:
                return L1.e(kotlin.coroutines.n.a, new com.quizlet.data.repository.term.f((com.quizlet.data.repository.term.g) this.d, this.b, this.c, null));
        }
    }
}
