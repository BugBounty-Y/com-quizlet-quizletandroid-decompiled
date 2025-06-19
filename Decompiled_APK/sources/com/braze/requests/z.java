package com.braze.requests;

import java.util.ArrayList;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class z implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;
    public final /* synthetic */ ArrayList c;

    public /* synthetic */ z(d dVar, ArrayList arrayList, int i) {
        this.a = i;
        this.b = dVar;
        this.c = arrayList;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return d.b(this.b, this.c);
            default:
                return d.a(this.b, this.c);
        }
    }
}
