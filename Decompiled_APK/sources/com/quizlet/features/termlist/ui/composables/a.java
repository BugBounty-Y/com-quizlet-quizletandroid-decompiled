package com.quizlet.features.termlist.ui.composables;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.functions.c b;
    public final /* synthetic */ long c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ String e;

    public /* synthetic */ a(kotlin.jvm.functions.c cVar, long j, boolean z, String str, int i) {
        this.a = i;
        this.b = cVar;
        this.c = j;
        this.d = z;
        this.e = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.invoke(Long.valueOf(this.c), Boolean.valueOf(this.d), this.e);
                break;
            default:
                this.b.invoke(Long.valueOf(this.c), Boolean.valueOf(this.d), this.e);
                break;
        }
        return Unit.a;
    }
}
