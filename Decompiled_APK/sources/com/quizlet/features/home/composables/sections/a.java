package com.quizlet.features.home.composables.sections;

import kotlin.jvm.functions.Function0;
import kotlinx.collections.immutable.e;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    public /* synthetic */ a(e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
        }
        return Integer.valueOf(this.b.size());
    }
}
